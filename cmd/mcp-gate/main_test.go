package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- Helper function tests ---

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"openid", []string{"openid"}},
		{"openid,profile", []string{"openid", "profile"}},
		{" openid , profile , email ", []string{"openid", "profile", "email"}},
		{"", nil},
		{" , , ", nil},
		{"single", []string{"single"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitCSV(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("splitCSV(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGetenvDefault(t *testing.T) {
	t.Setenv("TEST_GETENV_SET", "hello")

	if got := getenvDefault("TEST_GETENV_SET", "fallback"); got != "hello" {
		t.Errorf("getenvDefault = %q, want hello", got)
	}
	if got := getenvDefault("TEST_GETENV_UNSET", "fallback"); got != "fallback" {
		t.Errorf("getenvDefault = %q, want fallback", got)
	}
}

// --- Config validation tests ---

func defaultTestConfig(jwksURL, upstreamURL string) runConfig {
	u, _ := url.Parse(upstreamURL)
	return runConfig{
		listenAddr:          ":0",
		upstreamURL:         u,
		resourceURI:         "https://grafana-mcp.example.com",
		authServer:          "https://auth.example.com/application/o/test/",
		jwksURI:             jwksURL,
		expectedIssuer:      "https://auth.example.com/application/o/test/",
		expectedAudience:    "test-client-id",
		requiredScopes:      []string{"openid"},
		scopesSupported:     []string{"openid", "profile"},
		resourceName:        "Test MCP Server",
		jwksRefreshInterval: time.Hour,
		shutdownTimeout:     5 * time.Second,
		maxRequestBody:      10 << 20,
		rateLimitRPS:        1000, // High defaults — don't interfere with other tests
		rateLimitBurst:      2000,
		maxConcurrentPerIP:  100,
		maxTotalConnections: 1000,
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	if err := cfg.validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_MissingListenAddr(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.listenAddr = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected error for empty listen address")
	}
}

func TestValidate_NilUpstreamURL(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.upstreamURL = nil
	if err := cfg.validate(); err == nil {
		t.Error("expected error for nil upstream URL")
	}
}

func TestValidate_BadUpstreamScheme(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "ftp://localhost:8000")
	if err := cfg.validate(); err == nil {
		t.Error("expected error for ftp:// upstream scheme")
	}
}

func TestValidate_MissingResourceURI(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.resourceURI = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected error for empty resource URI")
	}
}

func TestValidate_MissingAuthServer(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.authServer = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected error for empty auth server")
	}
}

func TestValidate_MissingJWKSURI(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.jwksURI = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected error for empty JWKS URI")
	}
}

func TestValidate_MissingIssuer(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.expectedIssuer = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected error for empty expected issuer")
	}
}

func TestValidate_MissingAudience(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.expectedAudience = ""
	if err := cfg.validate(); err == nil {
		t.Error("expected error for empty expected audience")
	}
}

func TestValidate_BadRefreshInterval(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.jwksRefreshInterval = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero refresh interval")
	}
}

func TestValidate_BadShutdownTimeout(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.shutdownTimeout = -1
	if err := cfg.validate(); err == nil {
		t.Error("expected error for negative shutdown timeout")
	}
}

func TestValidate_BadMaxRequestBody(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.maxRequestBody = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero max request body")
	}
}

func TestValidate_BadRateLimitRPS(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.rateLimitRPS = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero rate limit RPS")
	}
}

func TestValidate_BadRateLimitBurst(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.rateLimitBurst = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero rate limit burst")
	}
}

func TestValidate_BadMaxConcurrentPerIP(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.maxConcurrentPerIP = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero max concurrent per IP")
	}
}

func TestValidate_BadMaxTotalConnections(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.maxTotalConnections = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero max total connections")
	}
}

// --- JWKS test infrastructure ---

// base64URLUint encodes a big.Int to unpadded base64url.
func base64URLUint(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

type testJWKS struct {
	privKey *rsa.PrivateKey
	server  *httptest.Server
}

func newTestJWKS(t *testing.T) *testJWKS {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "test-key-1",
				"use": "sig",
				"alg": "RS256",
				"n":   base64URLUint(privKey.N),
				"e":   base64URLUint(big.NewInt(int64(privKey.E))),
			},
		},
	}
	jwksBytes, _ := json.Marshal(jwks)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	t.Cleanup(srv.Close)

	return &testJWKS{privKey: privKey, server: srv}
}

// --- Server lifecycle tests ---

// startRun launches run() in a goroutine and waits for the server to be ready.
func startRun(t *testing.T, cfg *runConfig) (*runResult, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())

	ready := make(chan *runResult, 1)
	errCh := make(chan error, 1)

	go func() {
		_, err := run(ctx, cfg, ready)
		errCh <- err
	}()

	select {
	case result := <-ready:
		return result, cancel, errCh
	case err := <-errCh:
		cancel()
		t.Fatalf("run() failed before ready: %v", err)
		return nil, nil, nil
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for run() to be ready")
		return nil, nil, nil
	}
}

func TestRun_StartsAndShutdown(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	result, cancel, errCh := startRun(t, &cfg)

	if result.Addr == "" {
		t.Error("Addr is empty")
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return after cancel")
	}
}

func TestRun_HealthCheckReady(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://%s/healthz", result.Addr), http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("health check request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}
}

func TestRun_MetadataEndpoint(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://%s/.well-known/oauth-protected-resource", result.Addr), http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	if meta["resource"] != cfg.resourceURI {
		t.Errorf("resource = %q, want %q", meta["resource"], cfg.resourceURI)
	}
	if meta["resource_name"] != cfg.resourceName {
		t.Errorf("resource_name = %q, want %q", meta["resource_name"], cfg.resourceName)
	}

	servers, ok := meta["authorization_servers"].([]any)
	if !ok || len(servers) == 0 {
		t.Fatal("authorization_servers missing or empty")
	}
	if servers[0] != cfg.authServer {
		t.Errorf("authorization_servers[0] = %q, want %q", servers[0], cfg.authServer)
	}
}

func TestRun_UnauthenticatedRequest401(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	// Request without Authorization header should get 401
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://%s/mcp", result.Addr), http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("missing WWW-Authenticate header")
	}
	if !strings.Contains(wwwAuth, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want to contain Bearer", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "resource_metadata") {
		t.Errorf("WWW-Authenticate = %q, want to contain resource_metadata", wwwAuth)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "unauthorized" {
		t.Errorf("error = %q, want unauthorized", body["error"])
	}
}

func TestRun_InvalidConfigFails(t *testing.T) {
	cfg := runConfig{} // Everything empty
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, err := run(ctx, &cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("error = %q, want to contain 'invalid config'", err)
	}
}

func TestRun_BadJWKSURIFails(t *testing.T) {
	// Point JWKS at a closed server — should fail on init.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	closedURL := fmt.Sprintf("http://%s/jwks", ln.Addr().String())
	_ = ln.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(closedURL, upstream.URL)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, err = run(ctx, &cfg, nil)
	if err == nil {
		t.Fatal("expected error for unreachable JWKS URI")
	}
	if !strings.Contains(err.Error(), "auth middleware init") {
		t.Errorf("error = %q, want to contain 'auth middleware init'", err)
	}
}

func TestRun_SecurityHeadersOnAllRoutes(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":        "DENY",
		"Content-Security-Policy": "default-src 'none'",
		"Referrer-Policy":         "no-referrer",
	}

	// Security headers should be on all routes: catch-all, healthz, and metadata.
	paths := []string{"/anything", "/healthz", "/.well-known/oauth-protected-resource"}
	for _, path := range paths {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://%s%s", result.Addr, path), http.NoBody)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request to %s failed: %v", path, err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		for header, want := range expectedHeaders {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("%s on %s = %q, want %q", header, path, got, want)
			}
		}

		// HSTS should NOT be set — Traefik handles TLS termination
		if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
			t.Errorf("Strict-Transport-Security should not be set on %s, got %q", path, got)
		}
	}
}

// --- JWT signing helper for integration tests ---

func signTestToken(t *testing.T, privKey *rsa.PrivateKey, kid string, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "at+jwt"
	signed, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// --- loadConfig tests ---

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("LISTEN_ADDR", "0.0.0.0:8080")
	t.Setenv("UPSTREAM_URL", "http://localhost:8000")
	t.Setenv("RESOURCE_URI", "https://grafana-mcp.example.com")
	t.Setenv("AUTHORIZATION_SERVER", "https://auth.example.com/app/")
	t.Setenv("JWKS_URI", "https://auth.example.com/jwks/")
	t.Setenv("EXPECTED_ISSUER", "https://auth.example.com/app/")
	t.Setenv("EXPECTED_AUDIENCE", "test-client-id")
}

func TestLoadConfig_Defaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.listenAddr != "0.0.0.0:8080" {
		t.Errorf("listenAddr = %q, want 0.0.0.0:8080", cfg.listenAddr)
	}
	if cfg.upstreamURL.String() != "http://localhost:8000" {
		t.Errorf("upstreamURL = %q", cfg.upstreamURL.String())
	}
	if cfg.resourceURI != "https://grafana-mcp.example.com" {
		t.Errorf("resourceURI = %q", cfg.resourceURI)
	}
	if cfg.authServer != "https://auth.example.com/app/" {
		t.Errorf("authServer = %q", cfg.authServer)
	}
	if cfg.jwksURI != "https://auth.example.com/jwks/" {
		t.Errorf("jwksURI = %q", cfg.jwksURI)
	}
	if cfg.expectedIssuer != "https://auth.example.com/app/" {
		t.Errorf("expectedIssuer = %q", cfg.expectedIssuer)
	}
	if cfg.expectedAudience != "test-client-id" {
		t.Errorf("expectedAudience = %q", cfg.expectedAudience)
	}
	// Defaults
	if len(cfg.requiredScopes) != 1 || cfg.requiredScopes[0] != "openid" {
		t.Errorf("requiredScopes = %v, want [openid]", cfg.requiredScopes)
	}
	if len(cfg.scopesSupported) != 2 || cfg.scopesSupported[0] != "openid" || cfg.scopesSupported[1] != "profile" {
		t.Errorf("scopesSupported = %v, want [openid profile]", cfg.scopesSupported)
	}
	if cfg.resourceName != "Grafana MCP Server" {
		t.Errorf("resourceName = %q", cfg.resourceName)
	}
	if cfg.jwksRefreshInterval != time.Hour {
		t.Errorf("jwksRefreshInterval = %v, want 1h", cfg.jwksRefreshInterval)
	}
	if cfg.shutdownTimeout != 30*time.Second {
		t.Errorf("shutdownTimeout = %v, want 30s", cfg.shutdownTimeout)
	}
	if cfg.maxRequestBody != 10485760 {
		t.Errorf("maxRequestBody = %d, want 10485760", cfg.maxRequestBody)
	}
}

func TestLoadConfig_Optionals(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("REQUIRED_SCOPES", "openid,email")
	t.Setenv("SCOPES_SUPPORTED", "openid,email,profile")
	t.Setenv("RESOURCE_NAME", "Custom MCP")
	t.Setenv("JWKS_REFRESH_INTERVAL", "30m")
	t.Setenv("SHUTDOWN_TIMEOUT", "10s")
	t.Setenv("MAX_REQUEST_BODY", "5242880")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.requiredScopes) != 2 || cfg.requiredScopes[1] != "email" {
		t.Errorf("requiredScopes = %v", cfg.requiredScopes)
	}
	if len(cfg.scopesSupported) != 3 {
		t.Errorf("scopesSupported = %v", cfg.scopesSupported)
	}
	if cfg.resourceName != "Custom MCP" {
		t.Errorf("resourceName = %q", cfg.resourceName)
	}
	if cfg.jwksRefreshInterval != 30*time.Minute {
		t.Errorf("jwksRefreshInterval = %v, want 30m", cfg.jwksRefreshInterval)
	}
	if cfg.shutdownTimeout != 10*time.Second {
		t.Errorf("shutdownTimeout = %v, want 10s", cfg.shutdownTimeout)
	}
	if cfg.maxRequestBody != 5242880 {
		t.Errorf("maxRequestBody = %d, want 5242880", cfg.maxRequestBody)
	}
}

func TestLoadConfig_Errors(t *testing.T) {
	tests := []struct {
		name    string
		envMod  func(t *testing.T)
		wantErr string
	}{
		// Missing required vars
		{"missing_LISTEN_ADDR", func(t *testing.T) { t.Setenv("LISTEN_ADDR", "") }, "LISTEN_ADDR"},
		{"missing_UPSTREAM_URL", func(t *testing.T) { t.Setenv("UPSTREAM_URL", "") }, "UPSTREAM_URL"},
		{"missing_RESOURCE_URI", func(t *testing.T) { t.Setenv("RESOURCE_URI", "") }, "RESOURCE_URI"},
		{"missing_AUTHORIZATION_SERVER", func(t *testing.T) { t.Setenv("AUTHORIZATION_SERVER", "") }, "AUTHORIZATION_SERVER"},
		{"missing_JWKS_URI", func(t *testing.T) { t.Setenv("JWKS_URI", "") }, "JWKS_URI"},
		{"missing_EXPECTED_ISSUER", func(t *testing.T) { t.Setenv("EXPECTED_ISSUER", "") }, "EXPECTED_ISSUER"},
		{"missing_EXPECTED_AUDIENCE", func(t *testing.T) { t.Setenv("EXPECTED_AUDIENCE", "") }, "EXPECTED_AUDIENCE"},
		// URL validation
		{"JWKS_URI_not_https", func(t *testing.T) { t.Setenv("JWKS_URI", "http://auth.example.com/jwks/") }, "https"},
		{"JWKS_URI_invalid", func(t *testing.T) { t.Setenv("JWKS_URI", "://bad") }, "JWKS_URI is not a valid URL"},
		{"UPSTREAM_URL_bad_scheme", func(t *testing.T) { t.Setenv("UPSTREAM_URL", "ftp://localhost:8000") }, "http:// or https://"},
		{"UPSTREAM_URL_invalid", func(t *testing.T) { t.Setenv("UPSTREAM_URL", "://bad") }, "UPSTREAM_URL is not a valid URL"},
		{"RESOURCE_URI_invalid", func(t *testing.T) { t.Setenv("RESOURCE_URI", "://bad") }, "RESOURCE_URI is not a valid URL"},
		{"AUTHORIZATION_SERVER_invalid", func(t *testing.T) { t.Setenv("AUTHORIZATION_SERVER", "://bad") }, "AUTHORIZATION_SERVER is not a valid URL"},
		// Bad optional values
		{"bad_JWKS_REFRESH_INTERVAL", func(t *testing.T) { t.Setenv("JWKS_REFRESH_INTERVAL", "not-a-duration") }, "JWKS_REFRESH_INTERVAL"},
		{"bad_SHUTDOWN_TIMEOUT", func(t *testing.T) { t.Setenv("SHUTDOWN_TIMEOUT", "not-a-duration") }, "SHUTDOWN_TIMEOUT"},
		{"bad_MAX_REQUEST_BODY", func(t *testing.T) { t.Setenv("MAX_REQUEST_BODY", "not-a-number") }, "MAX_REQUEST_BODY"},
		{"bad_RATE_LIMIT_RPS", func(t *testing.T) { t.Setenv("RATE_LIMIT_RPS", "not-a-float") }, "RATE_LIMIT_RPS"},
		{"bad_RATE_LIMIT_BURST", func(t *testing.T) { t.Setenv("RATE_LIMIT_BURST", "not-a-number") }, "RATE_LIMIT_BURST"},
		{"bad_MAX_CONCURRENT_REQUESTS", func(t *testing.T) { t.Setenv("MAX_CONCURRENT_REQUESTS", "not-a-number") }, "MAX_CONCURRENT_REQUESTS"},
		{"bad_MAX_TOTAL_CONNECTIONS", func(t *testing.T) { t.Setenv("MAX_TOTAL_CONNECTIONS", "not-a-number") }, "MAX_TOTAL_CONNECTIONS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredEnv(t)
			tt.envMod(t)

			_, err := loadConfig()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig_UpstreamHTTPS(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("UPSTREAM_URL", "https://localhost:8000")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.upstreamURL.Scheme != "https" {
		t.Errorf("upstream scheme = %q, want https", cfg.upstreamURL.Scheme)
	}
}

// --- Additional run() tests ---

func TestRun_ListenFailure(t *testing.T) {
	// Occupy a port
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	cfg.listenAddr = ln.Addr().String()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, err = run(ctx, &cfg, nil)
	if err == nil {
		t.Fatal("expected error for occupied port")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Errorf("error = %q, want to contain 'listen'", err)
	}
}

func TestRun_AuthenticatedRequestProxied(t *testing.T) {
	jwks := newTestJWKS(t)

	var gotPath string
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	// Create valid JWT matching test config
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   cfg.expectedIssuer,
		"aud":   cfg.expectedAudience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"sub":   "test-user",
		"jti":   "test-jti",
		"scope": "openid profile",
	}
	token := signTestToken(t, jwks.privKey, "test-key-1", claims)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("http://%s/mcp/v1", result.Addr), http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200, body: %s", resp.StatusCode, body)
	}
	if gotPath != "/mcp/v1" {
		t.Errorf("upstream path = %q, want /mcp/v1", gotPath)
	}
	if gotAuth != "" {
		t.Error("Authorization header was not stripped before proxying")
	}
	if string(body) != "upstream-ok" {
		t.Errorf("body = %q, want upstream-ok", body)
	}
}

func TestRun_OversizedBodyRejected(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	cfg.maxRequestBody = 1024 // 1KB limit for test
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	// Create valid JWT
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   cfg.expectedIssuer,
		"aud":   cfg.expectedAudience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"sub":   "test-user",
		"jti":   "test-jti",
		"scope": "openid profile",
	}
	token := signTestToken(t, jwks.privKey, "test-key-1", claims)

	// Send body larger than maxRequestBody
	body := strings.NewReader(strings.Repeat("x", 2048))
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("http://%s/mcp", result.Addr), body)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	// Should get an error status (413 or 502 depending on where the limit triggers)
	if resp.StatusCode == http.StatusOK {
		t.Error("expected non-200 for oversized body, got 200")
	}
}

func TestRun_PathTraversalBlocked(t *testing.T) {
	jwks := newTestJWKS(t)

	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   cfg.expectedIssuer,
		"aud":   cfg.expectedAudience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"sub":   "test-user",
		"jti":   "test-jti",
		"scope": "openid profile",
	}
	token := signTestToken(t, jwks.privKey, "test-key-1", claims)

	// Path traversal attempt — Go's ServeMux cleans literal /../ sequences,
	// so they should be normalized before reaching the upstream.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://%s/mcp/../../../etc/passwd", result.Addr), http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Go's net/http client and ServeMux clean /../ — the upstream should
	// see a normalized path without traversal sequences
	if strings.Contains(gotPath, "..") {
		t.Errorf("path traversal not blocked: upstream saw %q", gotPath)
	}
}

func TestRun_RateLimiting429(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	cfg.rateLimitRPS = 1
	cfg.rateLimitBurst = 2
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	// Send 3 rapid requests to /healthz (no auth needed)
	for i := range 3 {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://%s/healthz", result.Addr), http.NoBody)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if i < 2 && resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
		if i == 2 && resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("request %d: status = %d, want 429", i, resp.StatusCode)
		}
	}
}
