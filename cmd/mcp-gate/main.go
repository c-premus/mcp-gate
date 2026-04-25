// Package main is the entrypoint for mcp-gate.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/c-premus/mcp-gate/internal/auth"
	"github.com/c-premus/mcp-gate/internal/metadata"
	"github.com/c-premus/mcp-gate/internal/metrics"
	otelsetup "github.com/c-premus/mcp-gate/internal/otel"
	"github.com/c-premus/mcp-gate/internal/proxy"
	"github.com/c-premus/mcp-gate/internal/ratelimit"
	"github.com/c-premus/mcp-gate/internal/realip"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// version is set at build time via -ldflags.
var version = "dev"

// runHealthcheck performs a local HTTP GET against /healthz and returns a
// process exit code. It is split out so defer can run before process exit.
//
// The dial target is derived from LISTEN_ADDR: when the host is empty or a
// wildcard (0.0.0.0, ::), localhost is used because wildcard binds aren't
// valid dial targets. When LISTEN_ADDR specifies a concrete IP
// (e.g. 172.20.0.133:8080), that host is dialed directly — hardcoding
// localhost would make the healthcheck fail forever on such configs and
// trigger rollback.
func runHealthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "localhost"
	}
	target := "http://" + net.JoinHostPort(host, port) + "/healthz"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		return 1
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// runConfig holds all configuration needed by run().
type runConfig struct {
	listenAddr          string
	upstreamURL         *url.URL
	resourceURI         string
	authServer          string
	jwksURI             string
	expectedIssuer      string
	expectedAudience    string
	requiredScopes      []string
	scopesSupported     []string
	resourceName        string
	jwksRefreshInterval time.Duration
	shutdownTimeout     time.Duration
	maxRequestBody      int64
	trustedProxies      []netip.Prefix
	rateLimitRPS        float64
	rateLimitBurst      int
	maxConcurrentPerIP  int
	maxTotalConnections int
	upstreamTimeout     time.Duration
	sseIdleTimeout      time.Duration
	readTimeout         time.Duration
	idleTimeout         time.Duration
	maxHeaderBytes      int
	metricsAddr         string
	otelEndpoint        string
	otelServiceName     string
	otelSampleRate      float64
}

// runResult holds the actual bound address after server startup.
type runResult struct {
	Addr        string
	MetricsAddr string
}

func main() {
	// Subcommands for distroless containers (no shell, no curl/wget)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-health", "healthcheck":
			os.Exit(runHealthcheck())
		case "--version", "-version":
			fmt.Println("mcp-gate " + version)
			os.Exit(0)
		}
	}

	// Configure slog FIRST — keyfunc uses slog.Default() for refresh errors
	var level slog.Level
	switch strings.ToLower(getenvDefault("LOG_LEVEL", "info")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	// Parse and validate configuration
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Create context that cancels on SIGTERM/SIGINT.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	_, err = run(ctx, &cfg, nil)
	cancel()
	if err != nil {
		log.Fatalf("fatal error: %v", err)
	}
}

// validate enforces the numeric range invariants that loadConfig cannot
// guarantee on its own. Required-string and URL-shape checks are intentionally
// omitted because loadConfig already performs them via requireEnv and
// url.ParseRequestURI before constructing a runConfig; duplicating them here
// drifted out of sync with loadConfig in the past. The single nil-pointer
// guard on upstreamURL remains because a test caller building a runConfig by
// hand can leave it zero, and proxy.New would nil-deref.
func (cfg *runConfig) validate() error {
	if cfg.upstreamURL == nil {
		return errors.New("upstream URL is required")
	}
	if cfg.jwksRefreshInterval <= 0 {
		return fmt.Errorf("JWKS refresh interval must be positive, got %s", cfg.jwksRefreshInterval)
	}
	if cfg.shutdownTimeout <= 0 {
		return fmt.Errorf("shutdown timeout must be positive, got %s", cfg.shutdownTimeout)
	}
	if cfg.maxRequestBody <= 0 {
		return fmt.Errorf("max request body must be positive, got %d", cfg.maxRequestBody)
	}
	if cfg.rateLimitRPS <= 0 {
		return fmt.Errorf("rate limit RPS must be positive, got %f", cfg.rateLimitRPS)
	}
	if cfg.rateLimitBurst <= 0 {
		return fmt.Errorf("rate limit burst must be positive, got %d", cfg.rateLimitBurst)
	}
	if cfg.maxConcurrentPerIP <= 0 {
		return fmt.Errorf("max concurrent requests per IP must be positive, got %d", cfg.maxConcurrentPerIP)
	}
	if cfg.maxTotalConnections <= 0 {
		return fmt.Errorf("max total connections must be positive, got %d", cfg.maxTotalConnections)
	}
	if cfg.upstreamTimeout <= 0 {
		return fmt.Errorf("upstream timeout must be positive, got %s", cfg.upstreamTimeout)
	}
	if cfg.sseIdleTimeout <= 0 {
		return fmt.Errorf("SSE idle timeout must be positive, got %s", cfg.sseIdleTimeout)
	}
	if cfg.readTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive, got %s", cfg.readTimeout)
	}
	if cfg.idleTimeout <= 0 {
		return fmt.Errorf("idle timeout must be positive, got %s", cfg.idleTimeout)
	}
	if cfg.maxHeaderBytes <= 0 {
		return fmt.Errorf("max header bytes must be positive, got %d", cfg.maxHeaderBytes)
	}
	return nil
}

// run starts the mcp-gate server and blocks until ctx is cancelled or a fatal
// error occurs. If ready is non-nil, the result is sent after the listener is bound;
// the channel should be buffered or actively drained to avoid blocking run.
func run(ctx context.Context, cfg *runConfig, ready chan<- *runResult) (result *runResult, err error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// MCP 2025-11-25 §"Token Handling" requires the RS to validate that tokens
	// were issued specifically for it per RFC 8707 §2, whose canonical form
	// is the resource's URI. Many OIDC providers (Authentik is one) emit
	// aud=<client_id> instead, which is substantively correct but not literally
	// the canonical URI. Log once at startup so operators who *can* configure
	// aud=<RESOURCE_URI> on the AS side see the gap; those who can't (Authentik)
	// can treat this as the documented trade-off captured in docs/spec.md.
	if cfg.expectedAudience != cfg.resourceURI {
		slog.Warn("audience not bound to canonical resource URI",
			"expected_audience", cfg.expectedAudience,
			"resource_uri", cfg.resourceURI,
			"reference", "RFC 8707 §2 / MCP 2025-11-25 Token Handling",
			"guidance", "prefer configuring the authorization server to emit aud=<RESOURCE_URI>",
		)
	}

	// Record build info metric
	metrics.Info.WithLabelValues(version).Set(1)

	// TRUSTED_PROXIES startup audit (resilience L6). When a deployment is
	// behind Cloudflare or any fronting proxy and this list is misconfigured,
	// every client IP collapses to the immediate-upstream proxy's IP and
	// per-IP rate limiting / concurrent-limit silently defeats. Surfacing the
	// parsed list at Info on every boot gives operators a config-audit trail;
	// the gauge keeps the same signal visible on the dashboard.
	cidrStrings := make([]string, 0, len(cfg.trustedProxies))
	for _, p := range cfg.trustedProxies {
		cidrStrings = append(cidrStrings, p.String())
	}
	slog.Info("trusted proxies configured",
		"count", len(cfg.trustedProxies),
		"cidrs", cidrStrings,
	)
	metrics.TrustedProxyCIDRs.Set(float64(len(cfg.trustedProxies)))

	// Start metrics server on separate port
	metricsSrv, err := metrics.NewServer(cfg.metricsAddr)
	if err != nil {
		return nil, fmt.Errorf("metrics server: %w", err)
	}
	metricsErrCh := make(chan error, 1)
	go func() {
		if err := metricsSrv.Serve(); err != nil {
			metricsErrCh <- fmt.Errorf("metrics server: %w", err)
		}
	}()
	// Guarantee the metrics server is stopped on any early-return error path.
	// On the graceful shutdown path, Shutdown is called explicitly below and
	// a second call here is a harmless no-op.
	defer func() {
		if err != nil {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer stopCancel()
			_ = metricsSrv.Shutdown(stopCtx)
		}
	}()

	// Initialize OTEL tracing (no-op if endpoint is empty)
	otelProvider, err := otelsetup.Setup(ctx, otelsetup.Config{
		Endpoint:    cfg.otelEndpoint,
		ServiceName: cfg.otelServiceName,
		SampleRate:  cfg.otelSampleRate,
		Version:     version,
	})
	if err != nil {
		return nil, fmt.Errorf("otel setup: %w", err)
	}

	// Build RFC 9728 metadata from config
	meta := metadata.ProtectedResourceMetadata{
		Resource:               cfg.resourceURI,
		AuthorizationServers:   []string{cfg.authServer},
		ScopesSupported:        cfg.scopesSupported,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           cfg.resourceName,
		ResourceDocumentation:  "https://github.com/grafana/mcp-grafana",
	}

	// Create JWKS context independent of signal context — cancelled explicitly
	// after server.Shutdown() so in-flight requests can still validate tokens.
	jwksCtx, jwksCancel := context.WithCancel(context.Background())
	defer jwksCancel()

	// Initialize auth middleware (blocking JWKS fetch)
	authMW, err := auth.NewMiddleware(auth.Config{
		Ctx:              jwksCtx,
		JWKSURI:          cfg.jwksURI,
		RefreshInterval:  cfg.jwksRefreshInterval,
		ExpectedIssuer:   cfg.expectedIssuer,
		ExpectedAudience: cfg.expectedAudience,
		RequiredScopes:   cfg.requiredScopes,
		ResourceURI:      cfg.resourceURI,
		Realm:            "grafana-mcp",
		ScopesSupported: strings.Join(cfg.scopesSupported, " "),
	})
	if err != nil {
		return nil, fmt.Errorf("auth middleware init: %w", err)
	}

	// Create reverse proxy with configurable upstream timeout
	// (JWKS key count metric is primed inside NewMiddleware and kept
	// current by the background polling goroutine it spawns.)
	tc := proxy.DefaultTransportConfig()
	tc.ResponseHeaderTimeout = cfg.upstreamTimeout
	tc.SSEIdleTimeout = cfg.sseIdleTimeout
	proxyHandler := proxy.New(cfg.upstreamURL, tc)

	// Register routes (Go 1.22+ method-specific patterns)
	mux := http.NewServeMux()

	metadataHandler, err := metadata.Handler(meta)
	if err != nil {
		return nil, fmt.Errorf("metadata handler: %w", err)
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", metadataHandler)

	// /healthz is reachable without authentication (Docker HEALTHCHECK, Traefik
	// probes), so the response bodies are deliberately generic — the status
	// code carries the signal. "jwks not ready" / subsystem-specific strings
	// would fingerprint the product and telegraph Authentik outages to any
	// unauthenticated probe.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !authMW.IsReady(r.Context()) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// All other routes: body-limit → request log → auth → proxy
	maxBody := cfg.maxRequestBody
	authedProxy := authMW.Handler(proxyHandler)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		authedProxy.ServeHTTP(w, r)
	}))

	// Wrap mux with security headers applied to all routes
	securityHeaders := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	})

	// Per-IP rate limiter (token bucket with stale entry eviction)
	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             cfg.rateLimitRPS,
		Burst:           cfg.rateLimitBurst,
		CleanupInterval: 5 * time.Minute,
		StaleAfter: 10 * time.Minute,
	})

	// Per-IP concurrent request limiter
	cl := ratelimit.NewConcurrentLimiter(cfg.maxConcurrentPerIP, cfg.maxTotalConnections)

	// Handler wrapping order (outermost → innermost):
	// otelhttp → realip → metrics → rateLimiter → concurrentLimiter → securityHeaders → mux
	handler := cl.Middleware(securityHeaders)
	handler = rl.Middleware(handler)
	handler = metrics.Middleware(handler)
	handler = realip.Middleware(cfg.trustedProxies)(handler)
	handler = otelhttp.NewHandler(handler, "mcp-gate")

	// Create server with timeouts (no WriteTimeout — kills SSE streams)
	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.readTimeout,
		IdleTimeout:       cfg.idleTimeout,
		MaxHeaderBytes:    cfg.maxHeaderBytes,
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				metrics.ActiveConnections.Inc()
			case http.StateClosed, http.StateHijacked:
				metrics.ActiveConnections.Dec()
			}
		},
	}

	// Bind listener so we know the actual address.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.listenAddr, err)
	}

	result = &runResult{
		Addr:        ln.Addr().String(),
		MetricsAddr: metricsSrv.Addr(),
	}

	// Signal readiness with bound address (for tests).
	if ready != nil {
		ready <- result
	}

	// Cancellable context for server lifecycle.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("mcp-gate starting",
			"version", version,
			"addr", result.Addr,
			"metrics_addr", result.MetricsAddr,
			"upstream", cfg.upstreamURL.String(),
			"resource_uri", cfg.resourceURI,
		)
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server error: %w", err)
		}
	}()

	// Wait for shutdown signal or fatal error.
	select {
	case <-ctx.Done():
		slog.Info("graceful shutdown started", "timeout", cfg.shutdownTimeout)
	case err := <-errCh:
		slog.Error("fatal server error", "error", err)
		cancel()
		return result, err
	case err := <-metricsErrCh:
		slog.Error("fatal metrics server error", "error", err)
		cancel()
		return result, err
	}

	// Graceful shutdown with an independent deadline per stage, so a slow
	// server drain cannot starve OTEL flush or metrics shutdown of their
	// budget. Order: server → OTEL flush → metrics server → JWKS cancel.
	shutdownStage := func(name string, fn func(context.Context) error) {
		stageCtx, stageCancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
		defer stageCancel()
		if err := fn(stageCtx); err != nil {
			slog.Warn("shutdown stage error", "stage", name, "error", err)
		}
	}

	shutdownStage("server", server.Shutdown)
	shutdownStage("otel", otelProvider.Shutdown)
	shutdownStage("metrics", metricsSrv.Shutdown)

	jwksCancel() // Cancel JWKS refresh AFTER server is drained
	slog.Info("server stopped")
	return result, nil
}

func loadConfig() (runConfig, error) {
	listenAddr, err := requireEnv("LISTEN_ADDR")
	if err != nil {
		return runConfig{}, err
	}
	upstreamRaw, err := requireEnv("UPSTREAM_URL")
	if err != nil {
		return runConfig{}, err
	}
	resourceURI, err := requireEnv("RESOURCE_URI")
	if err != nil {
		return runConfig{}, err
	}
	authServer, err := requireEnv("AUTHORIZATION_SERVER")
	if err != nil {
		return runConfig{}, err
	}
	jwksURI, err := requireEnv("JWKS_URI")
	if err != nil {
		return runConfig{}, err
	}
	expectedIssuer, err := requireEnv("EXPECTED_ISSUER")
	if err != nil {
		return runConfig{}, err
	}
	expectedAudience, err := requireEnv("EXPECTED_AUDIENCE")
	if err != nil {
		return runConfig{}, err
	}

	// Validate JWKS_URI scheme — MUST be https (MITM protection)
	jwksURL, err := url.ParseRequestURI(jwksURI)
	if err != nil {
		return runConfig{}, fmt.Errorf("JWKS_URI is not a valid URL: %w", err)
	}
	if jwksURL.Scheme != "https" {
		return runConfig{}, fmt.Errorf("JWKS_URI must use https:// scheme, got %s", jwksURL.Scheme)
	}

	// Validate UPSTREAM_URL scheme — http or https only (SSRF prevention)
	upstreamURL, err := url.ParseRequestURI(upstreamRaw)
	if err != nil {
		return runConfig{}, fmt.Errorf("UPSTREAM_URL is not a valid URL: %w", err)
	}
	if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
		return runConfig{}, fmt.Errorf("UPSTREAM_URL must use http:// or https:// scheme, got %s", upstreamURL.Scheme)
	}

	// Validate RESOURCE_URI
	if _, err := url.ParseRequestURI(resourceURI); err != nil {
		return runConfig{}, fmt.Errorf("RESOURCE_URI is not a valid URL: %w", err)
	}

	// Validate AUTHORIZATION_SERVER
	if _, err := url.ParseRequestURI(authServer); err != nil {
		return runConfig{}, fmt.Errorf("AUTHORIZATION_SERVER is not a valid URL: %w", err)
	}

	// Optional config with defaults
	requiredScopes := splitCSV(getenvDefault("REQUIRED_SCOPES", "openid"))
	scopesSupported := splitCSV(getenvDefault("SCOPES_SUPPORTED", "openid,profile"))
	resourceName := getenvDefault("RESOURCE_NAME", "Grafana MCP Server")

	jwksRefreshInterval, err := getenvDuration("JWKS_REFRESH_INTERVAL", "1h")
	if err != nil {
		return runConfig{}, err
	}

	shutdownTimeout, err := getenvDuration("SHUTDOWN_TIMEOUT", "30s")
	if err != nil {
		return runConfig{}, err
	}

	maxRequestBody, err := getenvInt64("MAX_REQUEST_BODY", "10485760")
	if err != nil {
		return runConfig{}, err
	}

	trustedProxies, err := realip.ParseCIDRs(splitCSV(os.Getenv("TRUSTED_PROXIES")))
	if err != nil {
		return runConfig{}, fmt.Errorf("TRUSTED_PROXIES: %w", err)
	}

	rateLimitRPS, err := getenvFloat("RATE_LIMIT_RPS", "10")
	if err != nil {
		return runConfig{}, err
	}

	rateLimitBurst, err := getenvInt("RATE_LIMIT_BURST", "20")
	if err != nil {
		return runConfig{}, err
	}

	maxConcurrentPerIP, err := getenvInt("MAX_CONCURRENT_REQUESTS", "100")
	if err != nil {
		return runConfig{}, err
	}

	maxTotalConnections, err := getenvInt("MAX_TOTAL_CONNECTIONS", "1000")
	if err != nil {
		return runConfig{}, err
	}

	timeouts, err := loadServerTimeouts()
	if err != nil {
		return runConfig{}, err
	}

	maxHeaderBytes, err := getenvInt("MAX_HEADER_BYTES", "65536")
	if err != nil {
		return runConfig{}, err
	}

	metricsAddr := getenvDefault("METRICS_ADDR", ":9090")
	otelEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") // intentionally optional
	otelServiceName := getenvDefault("OTEL_SERVICE_NAME", "mcp-gate")

	otelSampleRate, err := getenvFloat("OTEL_TRACE_SAMPLE_RATE", "1.0")
	if err != nil {
		return runConfig{}, err
	}
	if otelSampleRate < 0.0 || otelSampleRate > 1.0 {
		return runConfig{}, fmt.Errorf("OTEL_TRACE_SAMPLE_RATE must be between 0.0 and 1.0, got %f", otelSampleRate)
	}

	return runConfig{
		listenAddr:          listenAddr,
		upstreamURL:         upstreamURL,
		resourceURI:         resourceURI,
		authServer:          authServer,
		jwksURI:             jwksURI,
		expectedIssuer:      expectedIssuer,
		expectedAudience:    expectedAudience,
		requiredScopes:      requiredScopes,
		scopesSupported:     scopesSupported,
		resourceName:        resourceName,
		jwksRefreshInterval: jwksRefreshInterval,
		shutdownTimeout:     shutdownTimeout,
		maxRequestBody:      maxRequestBody,
		trustedProxies:      trustedProxies,
		rateLimitRPS:        rateLimitRPS,
		rateLimitBurst:      rateLimitBurst,
		maxConcurrentPerIP:  maxConcurrentPerIP,
		maxTotalConnections: maxTotalConnections,
		upstreamTimeout:     timeouts.upstream,
		sseIdleTimeout:      timeouts.sseIdle,
		readTimeout:         timeouts.read,
		idleTimeout:         timeouts.idle,
		maxHeaderBytes:      maxHeaderBytes,
		metricsAddr:         metricsAddr,
		otelEndpoint:        otelEndpoint,
		otelServiceName:     otelServiceName,
		otelSampleRate:      otelSampleRate,
	}, nil
}

func requireEnv(key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return val, nil
}

func getenvDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getenvDuration(key, fallback string) (time.Duration, error) {
	raw := getenvDefault(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration: %w", key, err)
	}
	return d, nil
}

func getenvInt(key, fallback string) (int, error) {
	raw := getenvDefault(key, fallback)
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid integer: %w", key, err)
	}
	return n, nil
}

func getenvInt64(key, fallback string) (int64, error) {
	raw := getenvDefault(key, fallback)
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid integer: %w", key, err)
	}
	return n, nil
}

func getenvFloat(key, fallback string) (float64, error) {
	raw := getenvDefault(key, fallback)
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid float: %w", key, err)
	}
	return f, nil
}

// serverTimeouts groups the four user-tunable timeouts that bound an HTTP
// request lifecycle. Extracted so loadConfig stays under the gocyclo
// threshold; the grouping is also a useful reading aid for operators
// auditing timeout policy.
type serverTimeouts struct {
	upstream time.Duration // first response byte from upstream
	sseIdle  time.Duration // idle gap between SSE bytes
	read     time.Duration // inbound request read deadline
	idle     time.Duration // keep-alive idle deadline
}

// loadServerTimeouts reads UPSTREAM_TIMEOUT, SSE_IDLE_TIMEOUT, READ_TIMEOUT
// and IDLE_TIMEOUT with sensible defaults. SSE_IDLE_TIMEOUT bounds the gap
// between bytes on a streamed text/event-stream response — without it, a
// silent SSE pins a goroutine, a TCP slot, and a concurrent-limit slot
// indefinitely (resilience M6).
func loadServerTimeouts() (serverTimeouts, error) {
	upstream, err := getenvDuration("UPSTREAM_TIMEOUT", "120s")
	if err != nil {
		return serverTimeouts{}, err
	}
	sseIdle, err := getenvDuration("SSE_IDLE_TIMEOUT", "5m")
	if err != nil {
		return serverTimeouts{}, err
	}
	read, err := getenvDuration("READ_TIMEOUT", "30s")
	if err != nil {
		return serverTimeouts{}, err
	}
	idle, err := getenvDuration("IDLE_TIMEOUT", "120s")
	if err != nil {
		return serverTimeouts{}, err
	}
	return serverTimeouts{upstream: upstream, sseIdle: sseIdle, read: read, idle: idle}, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func init() {
	// Suppress the default log prefix — we use slog for structured logging.
	// This only applies to log.Fatalf calls during startup config validation.
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(os.Stderr)
}
