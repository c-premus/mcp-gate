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
	trustedProxies      []*net.IPNet
	rateLimitRPS        float64
	rateLimitBurst      int
	maxConcurrentPerIP  int
	maxTotalConnections int
	upstreamTimeout     time.Duration
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
			addr := os.Getenv("LISTEN_ADDR")
			if addr == "" {
				addr = "0.0.0.0:8080"
			}
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				os.Exit(1)
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost:"+port+"/healthz", http.NoBody)
			if err != nil {
				os.Exit(1)
			}
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				os.Exit(1)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				os.Exit(1)
			}
			os.Exit(0)
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

// validate checks that all runConfig fields are sensible.
func (cfg *runConfig) validate() error {
	if cfg.listenAddr == "" {
		return errors.New("listen address is required")
	}
	if cfg.upstreamURL == nil {
		return errors.New("upstream URL is required")
	}
	if s := cfg.upstreamURL.Scheme; s != "http" && s != "https" {
		return fmt.Errorf("upstream URL must use http:// or https://, got %s", s)
	}
	if cfg.resourceURI == "" {
		return errors.New("resource URI is required")
	}
	if cfg.authServer == "" {
		return errors.New("authorization server is required")
	}
	if cfg.jwksURI == "" {
		return errors.New("JWKS URI is required")
	}
	if cfg.expectedIssuer == "" {
		return errors.New("expected issuer is required")
	}
	if cfg.expectedAudience == "" {
		return errors.New("expected audience is required")
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
// error occurs. If ready is non-nil, the result is sent after the listener is bound.
func run(ctx context.Context, cfg *runConfig, ready chan<- *runResult) (*runResult, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Record build info metric
	metrics.Info.WithLabelValues(version).Set(1)

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
		ScopesSupported:  strings.Join(cfg.scopesSupported, " "),
		TrustedProxies:   cfg.trustedProxies,
	})
	if err != nil {
		return nil, fmt.Errorf("auth middleware init: %w", err)
	}

	// Create reverse proxy with configurable upstream timeout
	// (JWKS key count metric is primed inside NewMiddleware and kept
	// current by the background polling goroutine it spawns.)
	tc := proxy.DefaultTransportConfig()
	tc.ResponseHeaderTimeout = cfg.upstreamTimeout
	proxyHandler := proxy.New(cfg.upstreamURL, tc)

	// Register routes (Go 1.22+ method-specific patterns)
	mux := http.NewServeMux()

	metadataHandler, err := metadata.Handler(meta)
	if err != nil {
		return nil, fmt.Errorf("metadata handler: %w", err)
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", metadataHandler)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !authMW.IsReady() {
			http.Error(w, "jwks not ready", http.StatusServiceUnavailable)
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
		StaleAfter:      10 * time.Minute,
		TrustedProxies:  cfg.trustedProxies,
	})

	// Per-IP concurrent request limiter
	cl := ratelimit.NewConcurrentLimiter(cfg.maxConcurrentPerIP, cfg.maxTotalConnections, cfg.trustedProxies)

	// Handler wrapping order (outermost → innermost):
	// otelhttp → metrics → rateLimiter → concurrentLimiter → securityHeaders → mux
	handler := cl.Middleware(securityHeaders)
	handler = rl.Middleware(handler)
	handler = metrics.Middleware(handler, cfg.trustedProxies)
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

	result := &runResult{
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
		if err := server.Serve(ln); err != http.ErrServerClosed {
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

	// Graceful shutdown with timeout.
	// Order: server → OTEL flush → metrics server → JWKS cancel
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Warn("shutdown forced — connections closed", "error", err)
	}

	if err := otelProvider.Shutdown(shutdownCtx); err != nil {
		slog.Warn("otel shutdown error", "error", err)
	}

	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("metrics server shutdown error", "error", err)
	}

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

	upstreamTimeout, err := getenvDuration("UPSTREAM_TIMEOUT", "120s")
	if err != nil {
		return runConfig{}, err
	}

	readTimeout, err := getenvDuration("READ_TIMEOUT", "30s")
	if err != nil {
		return runConfig{}, err
	}

	idleTimeout, err := getenvDuration("IDLE_TIMEOUT", "120s")
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
		upstreamTimeout:     upstreamTimeout,
		readTimeout:         readTimeout,
		idleTimeout:         idleTimeout,
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
