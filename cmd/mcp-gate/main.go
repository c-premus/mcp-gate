// Package main is the entrypoint for mcp-gate.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chris/mcp-gate/internal/auth"
	"github.com/chris/mcp-gate/internal/metadata"
	"github.com/chris/mcp-gate/internal/proxy"
)

// version is set at build time via -ldflags.
var version = "dev"

type config struct {
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
}

func main() {
	// Subcommands for distroless containers (no shell, no curl/wget)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-health", "healthcheck":
			resp, err := http.Get("http://localhost:8080/healthz")
			if err != nil || resp.StatusCode != http.StatusOK {
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
	cfg := loadConfig()

	// Build RFC 9728 metadata from config
	meta := metadata.ProtectedResourceMetadata{
		Resource:               cfg.resourceURI,
		AuthorizationServers:   []string{cfg.authServer},
		ScopesSupported:        cfg.scopesSupported,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           cfg.resourceName,
		ResourceDocumentation:  "https://github.com/grafana/mcp-grafana",
	}

	// Create JWKS context — cancel stops background refresh
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
	})
	if err != nil {
		log.Fatalf("auth middleware init failed: %v", err)
	}

	// Create reverse proxy
	proxyHandler := proxy.New(cfg.upstreamURL)

	// Register routes (Go 1.22+ method-specific patterns)
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/oauth-protected-resource", metadata.Handler(meta))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !authMW.IsReady() {
			http.Error(w, "jwks not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// All other routes: body-limit → security headers → auth → proxy
	maxBody := cfg.maxRequestBody
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		authMW.Handler(proxyHandler).ServeHTTP(w, r)
	}))

	// Create server with timeouts (no WriteTimeout — kills SSE streams)
	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		slog.Info("mcp-gate starting",
			"addr", cfg.listenAddr,
			"upstream", cfg.upstreamURL.String(),
			"resource_uri", cfg.resourceURI,
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-sigCh
	slog.Info("graceful shutdown started", "timeout", cfg.shutdownTimeout)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Warn("shutdown forced — connections closed", "error", err)
	}

	jwksCancel() // Cancel JWKS refresh AFTER server is drained
	slog.Info("server stopped")
}

func loadConfig() config {
	listenAddr := mustGetenv("LISTEN_ADDR")
	upstreamRaw := mustGetenv("UPSTREAM_URL")
	resourceURI := mustGetenv("RESOURCE_URI")
	authServer := mustGetenv("AUTHORIZATION_SERVER")
	jwksURI := mustGetenv("JWKS_URI")
	expectedIssuer := mustGetenv("EXPECTED_ISSUER")
	expectedAudience := mustGetenv("EXPECTED_AUDIENCE")

	// Validate JWKS_URI scheme — MUST be https (MITM protection)
	jwksURL, err := url.ParseRequestURI(jwksURI)
	if err != nil {
		log.Fatalf("JWKS_URI is not a valid URL: %v", err)
	}
	if jwksURL.Scheme != "https" {
		log.Fatalf("JWKS_URI must use https:// scheme, got %s", jwksURL.Scheme)
	}

	// Validate UPSTREAM_URL scheme — http or https only (SSRF prevention)
	upstreamURL, err := url.ParseRequestURI(upstreamRaw)
	if err != nil {
		log.Fatalf("UPSTREAM_URL is not a valid URL: %v", err)
	}
	if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
		log.Fatalf("UPSTREAM_URL must use http:// or https:// scheme, got %s", upstreamURL.Scheme)
	}

	// Validate RESOURCE_URI
	if _, err := url.ParseRequestURI(resourceURI); err != nil {
		log.Fatalf("RESOURCE_URI is not a valid URL: %v", err)
	}

	// Validate AUTHORIZATION_SERVER
	if _, err := url.ParseRequestURI(authServer); err != nil {
		log.Fatalf("AUTHORIZATION_SERVER is not a valid URL: %v", err)
	}

	// Optional config with defaults
	requiredScopes := splitCSV(getenvDefault("REQUIRED_SCOPES", "openid"))
	scopesSupported := splitCSV(getenvDefault("SCOPES_SUPPORTED", "openid,profile"))
	resourceName := getenvDefault("RESOURCE_NAME", "Grafana MCP Server")

	jwksRefreshInterval, err := time.ParseDuration(getenvDefault("JWKS_REFRESH_INTERVAL", "1h"))
	if err != nil {
		log.Fatalf("JWKS_REFRESH_INTERVAL is not a valid duration: %v", err)
	}

	shutdownTimeout, err := time.ParseDuration(getenvDefault("SHUTDOWN_TIMEOUT", "30s"))
	if err != nil {
		log.Fatalf("SHUTDOWN_TIMEOUT is not a valid duration: %v", err)
	}

	maxRequestBody, err := strconv.ParseInt(getenvDefault("MAX_REQUEST_BODY", "10485760"), 10, 64)
	if err != nil {
		log.Fatalf("MAX_REQUEST_BODY is not a valid integer: %v", err)
	}

	return config{
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
	}
}

func mustGetenv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return val
}

func getenvDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
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

