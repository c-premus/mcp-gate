package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
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
		upstreamTimeout:     120 * time.Second,
		sseIdleTimeout:      5 * time.Minute,
		readTimeout:         30 * time.Second,
		idleTimeout:         120 * time.Second,
		maxHeaderBytes:      131072,
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	if err := cfg.validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// String-emptiness and URL-scheme checks are covered by TestLoadConfig_Errors;
// validate() only re-enforces the nil-pointer and positivity invariants that
// a hand-built runConfig (test caller) can violate.

func TestValidate_NilUpstreamURL(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.upstreamURL = nil
	if err := cfg.validate(); err == nil {
		t.Error("expected error for nil upstream URL")
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

func TestValidate_BadUpstreamTimeout(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.upstreamTimeout = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero upstream timeout")
	}
}

func TestValidate_BadSSEIdleTimeout(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.sseIdleTimeout = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero SSE idle timeout")
	}
}

func TestValidate_BadReadTimeout(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.readTimeout = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero read timeout")
	}
}

func TestValidate_BadIdleTimeout(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.idleTimeout = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero idle timeout")
	}
}

func TestValidate_BadMaxHeaderBytes(t *testing.T) {
	cfg := defaultTestConfig("https://example.com/jwks", "http://localhost:8000")
	cfg.maxHeaderBytes = 0
	if err := cfg.validate(); err == nil {
		t.Error("expected error for zero max header bytes")
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

	// Security headers apply to every route, including the well-known subtree's
	// 404 — a response body an attacker can reach unauthenticated still needs
	// nosniff and a null CSP.
	paths := []string{
		"/anything",
		"/healthz",
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/not-served",
	}
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

// signTestToken signs a JWT for tests. The kid parameter remains explicit even
// though every current call site passes "test-key-1": tests that exercise
// unknown-kid / rotation paths will pass other values.
//
//nolint:unparam // kid is part of the helper's contract; future callers will vary it.
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
	if cfg.upstreamTimeout != 120*time.Second {
		t.Errorf("upstreamTimeout = %v, want 120s", cfg.upstreamTimeout)
	}
	if cfg.sseIdleTimeout != 5*time.Minute {
		t.Errorf("sseIdleTimeout = %v, want 5m", cfg.sseIdleTimeout)
	}
	if cfg.readTimeout != 30*time.Second {
		t.Errorf("readTimeout = %v, want 30s", cfg.readTimeout)
	}
	if cfg.idleTimeout != 120*time.Second {
		t.Errorf("idleTimeout = %v, want 120s", cfg.idleTimeout)
	}
	if cfg.maxHeaderBytes != 131072 {
		t.Errorf("maxHeaderBytes = %d, want 131072", cfg.maxHeaderBytes)
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
	t.Setenv("UPSTREAM_TIMEOUT", "60s")
	t.Setenv("SSE_IDLE_TIMEOUT", "10m")
	t.Setenv("READ_TIMEOUT", "15s")
	t.Setenv("IDLE_TIMEOUT", "90s")
	t.Setenv("MAX_HEADER_BYTES", "32768")

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
	if cfg.upstreamTimeout != 60*time.Second {
		t.Errorf("upstreamTimeout = %v, want 60s", cfg.upstreamTimeout)
	}
	if cfg.sseIdleTimeout != 10*time.Minute {
		t.Errorf("sseIdleTimeout = %v, want 10m", cfg.sseIdleTimeout)
	}
	if cfg.readTimeout != 15*time.Second {
		t.Errorf("readTimeout = %v, want 15s", cfg.readTimeout)
	}
	if cfg.idleTimeout != 90*time.Second {
		t.Errorf("idleTimeout = %v, want 90s", cfg.idleTimeout)
	}
	if cfg.maxHeaderBytes != 32768 {
		t.Errorf("maxHeaderBytes = %d, want 32768", cfg.maxHeaderBytes)
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
		{"bad_UPSTREAM_TIMEOUT", func(t *testing.T) { t.Setenv("UPSTREAM_TIMEOUT", "not-a-duration") }, "UPSTREAM_TIMEOUT"},
		{"bad_READ_TIMEOUT", func(t *testing.T) { t.Setenv("READ_TIMEOUT", "not-a-duration") }, "READ_TIMEOUT"},
		{"bad_IDLE_TIMEOUT", func(t *testing.T) { t.Setenv("IDLE_TIMEOUT", "not-a-duration") }, "IDLE_TIMEOUT"},
		{"bad_MAX_HEADER_BYTES", func(t *testing.T) { t.Setenv("MAX_HEADER_BYTES", "not-a-number") }, "MAX_HEADER_BYTES"},
		// OTEL_TRACE_SAMPLE_RATE out of range
		{"OTEL_TRACE_SAMPLE_RATE_negative", func(t *testing.T) { t.Setenv("OTEL_TRACE_SAMPLE_RATE", "-0.1") }, "OTEL_TRACE_SAMPLE_RATE"},
		{"OTEL_TRACE_SAMPLE_RATE_above_1", func(t *testing.T) { t.Setenv("OTEL_TRACE_SAMPLE_RATE", "1.1") }, "OTEL_TRACE_SAMPLE_RATE"},
		{"bad_OTEL_TRACE_SAMPLE_RATE", func(t *testing.T) { t.Setenv("OTEL_TRACE_SAMPLE_RATE", "not-a-float") }, "OTEL_TRACE_SAMPLE_RATE"},
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

func TestLoadConfig_OTELSampleRateBoundaries(t *testing.T) {
	for _, rate := range []string{"0.0", "1.0", "0.5"} {
		t.Run(rate, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("OTEL_TRACE_SAMPLE_RATE", rate)

			_, err := loadConfig()
			if err != nil {
				t.Fatalf("OTEL_TRACE_SAMPLE_RATE=%s should be valid, got error: %v", rate, err)
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

	// upstream handler runs on its own goroutine; the test reader observes
	// the captured fields after the request completes. Without a mutex the
	// race detector (and -race CI) flags the cross-goroutine write/read pair.
	var (
		mu      sync.Mutex
		gotPath string
		gotAuth string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
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

	mu.Lock()
	gotPathSnap := gotPath
	gotAuthSnap := gotAuth
	mu.Unlock()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200, body: %s", resp.StatusCode, body)
	}
	if gotPathSnap != "/mcp/v1" {
		t.Errorf("upstream path = %q, want /mcp/v1", gotPathSnap)
	}
	if gotAuthSnap != "" {
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

	// http.MaxBytesReader trips inside the proxy's body-relay path, which
	// httputil.ReverseProxy surfaces to our ErrorHandler as a read error. This
	// used to be reported as 502 upstream_error, and this assertion pinned that
	// deliberately — its previous comment asked to be told if anyone switched
	// to 413, because it is a contract change.
	//
	// It was switched, on purpose: 502 blamed a healthy upstream for the
	// client's oversized request and inflated the 5xx ratio the deploy alert
	// watches, and MCP 2026-07-28 asks intermediaries to "return an appropriate
	// HTTP error status for validation failures". The assertion stays, now
	// pinning 413, for the same reason it existed before.
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d (oversized body is a client error, not an upstream one)",
			resp.StatusCode, http.StatusRequestEntityTooLarge)
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

// --- TRUSTED_PROXIES startup observability (B3 / resilience L6) ---

func TestLoadConfig_TrustedProxiesEmpty(t *testing.T) {
	setRequiredEnv(t)
	// TRUSTED_PROXIES intentionally unset.

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := len(cfg.trustedProxies); got != 0 {
		t.Errorf("trustedProxies len = %d, want 0", got)
	}
}

func TestLoadConfig_TrustedProxiesParsed(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8,192.168.0.0/16")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := len(cfg.trustedProxies); got != 2 {
		t.Fatalf("trustedProxies len = %d, want 2", got)
	}
	want := []string{"10.0.0.0/8", "192.168.0.0/16"}
	for i, p := range cfg.trustedProxies {
		if p.String() != want[i] {
			t.Errorf("trustedProxies[%d] = %q, want %q", i, p.String(), want[i])
		}
	}
}

// --- Shutdown ordering (audit M7) ---

// stageCapture is a slog.Handler that records every log record carrying a
// "stage" attribute. shutdownStage emits a Warn with "stage" set on error,
// so capturing those records in order tells us the actual shutdown sequence.
type stageCapture struct {
	mu    sync.Mutex
	stages []string
	// orderedRecords keeps every record in the order it was logged; useful
	// for diagnostics if stage assertions fail.
	messages []string
}

func (h *stageCapture) Enabled(_ context.Context, _ slog.Level) bool { return true }

// Handle implements slog.Handler. The slog.Record value-receiver matches the
// interface signature; it is large but cannot be passed by pointer here.
//
//nolint:gocritic // hugeParam is dictated by the slog.Handler contract.
func (h *stageCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages, r.Message)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "stage" {
			h.stages = append(h.stages, a.Value.String())
			return false
		}
		return true
	})
	return nil
}

func (h *stageCapture) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *stageCapture) WithGroup(_ string) slog.Handler      { return h }

// snapshot returns a copy of the captured stage names and all log messages,
// in the order they were observed.
func (h *stageCapture) snapshot() (stages, messages []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.stages), slices.Clone(h.messages)
}

// TestRun_ShutdownStageOrder asserts that run()'s graceful shutdown sequence
// runs stages in the documented order: server → otel → metrics → JWKS.
//
// The assertion mechanism is shutdownStage's per-stage Warn log: it fires
// only on error, so the test deliberately induces errors in each stage by
// driving the per-stage shutdown timeout to a value smaller than the work
// each stage has to do:
//
//   - server stage: a long-running upstream handler keeps a request in flight,
//     so server.Shutdown blocks until ctx is cancelled and returns
//     context.DeadlineExceeded.
//   - otel stage: the BatchSpanProcessor's Shutdown calls ForceFlush, which
//     respects the ctx; with a tiny shutdown timeout it returns
//     context.DeadlineExceeded.
//
// The metrics stage is harder to force into an error reliably (its handler
// set is fast and there's no in-flight request to drain), and JWKS shutdown
// is a context cancel with no observable log. We therefore assert the
// captured server/otel ordering and verify the metrics server is still
// shut down at the end (port becomes unreachable). That covers the critical
// production invariant: server stops accepting traffic before metrics
// scraping stops collecting final data.
func TestRun_ShutdownStageOrder(t *testing.T) {
	// Swap in a capturing slog handler for the duration of the test.
	prevDefault := slog.Default()
	stageCap := &stageCapture{}
	slog.SetDefault(slog.New(stageCap))
	t.Cleanup(func() { slog.SetDefault(prevDefault) })

	jwks := newTestJWKS(t)

	// Upstream that hangs until the test releases it. The hung connection
	// keeps server.Shutdown() blocked until its tiny stageCtx expires.
	// inFlight signals that the upstream handler has actually begun serving
	// the request — without this synchronization, shutdown can race the
	// client request and run while no connection is open.
	release := make(chan struct{})
	inFlight := make(chan struct{})
	closeReleaseOnce := sync.Once{}
	closeRelease := func() { closeReleaseOnce.Do(func() { close(release) }) }
	t.Cleanup(closeRelease)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-inFlight:
			// already signalled (subsequent request, e.g. retry)
		default:
			close(inFlight)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	// otelEndpoint set to a closed local address: Setup succeeds (no spans
	// exported eagerly), but the BatchSpanProcessor's Shutdown ForceFlush
	// call fails when ctx is tiny.
	cfg.otelEndpoint = "http://127.0.0.1:1"
	cfg.otelServiceName = "mcp-gate-test"
	cfg.otelSampleRate = 1.0
	// Tiny per-stage timeout. Validate() requires shutdownTimeout > 0; 1ms
	// is small enough that any stage with work to do (in-flight conn,
	// ForceFlush) deterministically times out.
	cfg.shutdownTimeout = time.Millisecond

	result, cancel, errCh := startRun(t, &cfg)

	// Issue a hung authenticated request through the proxy so the server
	// has an in-flight connection to drain.
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

	clientErrCh := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(),
			http.MethodGet,
			fmt.Sprintf("http://%s/mcp", result.Addr),
			http.NoBody)
		req.Header.Set("Authorization", "Bearer "+token)
		// Use a fresh client so DefaultClient's persistent state isn't
		// affected by the deliberate hang.
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		clientErrCh <- err
	}()

	// Capture metrics server addr before shutdown so we can probe it
	// post-shutdown.
	metricsAddr := result.MetricsAddr

	// Wait for the upstream handler to actually have the request in flight.
	// inFlight is closed inside the upstream handler; once it fires, the
	// proxy → upstream connection is open and server.Shutdown will block on
	// it until the (tiny) stageCtx expires.
	select {
	case <-inFlight:
	case <-time.After(2 * time.Second):
		closeRelease()
		t.Fatal("upstream did not receive request before shutdown deadline")
	}

	// Trigger graceful shutdown.
	cancel()

	// Wait for run() to return; release the hung handler so the upstream
	// goroutine doesn't leak.
	select {
	case <-time.After(5 * time.Second):
		closeRelease()
		t.Fatal("run() did not return after shutdown")
	case err := <-errCh:
		closeRelease()
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	}

	// Drain the client goroutine.
	select {
	case <-clientErrCh:
	case <-time.After(2 * time.Second):
		t.Log("client goroutine did not return; not fatal for ordering check")
	}

	// Inspect captured stage order.
	stages, msgs := stageCap.snapshot()

	// Must have observed at least the server stage error to validate ordering.
	idxServer := slices.Index(stages, "server")
	idxOtel := slices.Index(stages, "otel")
	if idxServer < 0 {
		t.Fatalf("expected 'server' stage warn in captured logs; stages=%v messages=%v",
			stages, msgs)
	}
	// otel stage should also have errored given the closed-port endpoint
	// + tiny shutdown timeout. If otel managed to flush in time we still
	// catch a regression where server runs after otel because idxServer
	// would then be >= idxOtel.
	if idxOtel >= 0 && idxServer >= idxOtel {
		t.Errorf("server stage must precede otel stage; stages=%v", stages)
	}

	// Cross-check via side effect: after run() returns, the metrics server
	// should be unbound. This is the structural confirmation that the
	// metrics stage ran (regardless of whether it logged a warn).
	dialer := &net.Dialer{Timeout: 200 * time.Millisecond}
	c, err := dialer.DialContext(t.Context(), "tcp", metricsAddr)
	if err == nil {
		_ = c.Close()
		t.Errorf("metrics server still reachable on %s after run() returned; metrics shutdown did not run",
			metricsAddr)
	}
}

// --- Redis rate-limit backend selection ---

func TestRun_RedisBackendStartsAndServes(t *testing.T) {
	mr := miniredis.RunT(t)

	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	cfg.redisAddr = mr.Addr()
	cfg.redisTimeout = 100 * time.Millisecond
	cfg.redisKeyPrefix = "test:rl:"

	result, cancel, errCh := startRun(t, &cfg)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://"+result.Addr+"/.well-known/oauth-protected-resource", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("metadata request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("metadata status = %d, want 200", resp.StatusCode)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("run() returned error: %v", err)
	}
}

func TestRun_RedisAuthFailsWhenWrongPassword(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("correct-horse")

	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	cfg.redisAddr = mr.Addr()
	cfg.redisPassword = "wrong"
	cfg.redisTimeout = 100 * time.Millisecond

	_, err := run(t.Context(), &cfg, nil)
	if err == nil {
		t.Fatal("run() with bad Redis password: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "redis ping") {
		t.Errorf("error should mention redis ping, got: %v", err)
	}
}

func TestRun_RedisUnreachableFails(t *testing.T) {
	// Reserve a TCP port and immediately close it so connecting refuses.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	cfg.redisAddr = addr
	cfg.redisTimeout = 100 * time.Millisecond

	_, err = run(t.Context(), &cfg, nil)
	if err == nil {
		t.Fatal("run() with unreachable Redis: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "redis ping") {
		t.Errorf("error should mention redis ping, got: %v", err)
	}
}

func TestLoadConfig_RedisDefaults(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("REDIS_ADDR", "")
	t.Setenv("REDIS_USERNAME", "")
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("REDIS_DB", "")
	t.Setenv("REDIS_TIMEOUT", "")
	t.Setenv("REDIS_KEY_PREFIX", "")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.redisAddr != "" {
		t.Errorf("redisAddr = %q, want empty", cfg.redisAddr)
	}
	if cfg.redisUsername != "" {
		t.Errorf("redisUsername = %q, want empty", cfg.redisUsername)
	}
	if cfg.redisPassword != "" {
		t.Errorf("redisPassword = %q, want empty", cfg.redisPassword)
	}
	if cfg.redisDB != 0 {
		t.Errorf("redisDB = %d, want 0", cfg.redisDB)
	}
	if cfg.redisTimeout != 100*time.Millisecond {
		t.Errorf("redisTimeout = %v, want 100ms", cfg.redisTimeout)
	}
	if cfg.redisKeyPrefix != "mcpgate:rl:" {
		t.Errorf("redisKeyPrefix = %q, want mcpgate:rl:", cfg.redisKeyPrefix)
	}
}

func TestLoadConfig_RedisOverrides(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("REDIS_ADDR", "redis.internal:6390")
	t.Setenv("REDIS_USERNAME", "mcpgate")
	t.Setenv("REDIS_PASSWORD", "p@s/s:w?rd#1") // chars that would need URL encoding
	t.Setenv("REDIS_DB", "3")
	t.Setenv("REDIS_TIMEOUT", "250ms")
	t.Setenv("REDIS_KEY_PREFIX", "custom:")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.redisAddr != "redis.internal:6390" {
		t.Errorf("redisAddr = %q", cfg.redisAddr)
	}
	if cfg.redisUsername != "mcpgate" {
		t.Errorf("redisUsername = %q", cfg.redisUsername)
	}
	if cfg.redisPassword != "p@s/s:w?rd#1" {
		t.Errorf("redisPassword = %q (the special-character round-trip is the load-bearing assertion)", cfg.redisPassword)
	}
	if cfg.redisDB != 3 {
		t.Errorf("redisDB = %d", cfg.redisDB)
	}
	if cfg.redisTimeout != 250*time.Millisecond {
		t.Errorf("redisTimeout = %v", cfg.redisTimeout)
	}
	if cfg.redisKeyPrefix != "custom:" {
		t.Errorf("redisKeyPrefix = %q", cfg.redisKeyPrefix)
	}
}

func TestLoadConfig_RedisDBNonInteger(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("REDIS_DB", "not-a-number")

	if _, err := loadConfig(); err == nil {
		t.Fatal("expected error for non-integer REDIS_DB")
	}
}

// TestWarnOfflineAccess covers the MCP 2026-07-28 SHOULD NOT that a protected
// resource must not advertise offline_access. The check is advisory, so the
// only observable behavior is the log line — which makes it exactly the kind of
// thing that rots silently without a test.
//
// Not parallel: it swaps the default slog handler.
func TestWarnOfflineAccess(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		wantWarn bool
	}{
		{"typical scopes", []string{"openid", "profile"}, false},
		{"empty", nil, false},
		{"offline_access present", []string{"openid", "offline_access"}, true},
		{"offline_access alone", []string{"offline_access"}, true},
		{
			// Substring matches must not trigger: these are distinct scopes.
			name:     "similar scope names do not match",
			scopes:   []string{"offline", "offline_access_granted"},
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			warnOfflineAccess("SCOPES_SUPPORTED", tt.scopes)

			got := strings.Contains(buf.String(), "offline_access advertised")
			if got != tt.wantWarn {
				t.Errorf("warned = %v, want %v\n  scopes: %v\n  log: %s",
					got, tt.wantWarn, tt.scopes, buf.String())
			}
			if tt.wantWarn && !strings.Contains(buf.String(), "SCOPES_SUPPORTED") {
				t.Errorf("warning does not name the env var to edit: %s", buf.String())
			}
		})
	}
}

// TestRun_WellKnownSubtree covers RFC 9728 §3.1 path insertion end to end.
//
// Clients probe the path-inserted form BEFORE the root form, so a deployment
// whose RESOURCE_URI carries a path must answer there. A root-mounted
// deployment — this one — must register nothing extra, and everything else
// under the well-known prefix must 404 rather than fall through to the auth
// middleware and come back as a 401 challenge. Telling a client "authenticate
// and retry" about a metadata document that does not exist is misleading and
// can push a naive implementation into a discovery loop.
func TestRun_WellKnownSubtree(t *testing.T) {
	const wellKnown = "/.well-known/oauth-protected-resource"

	tests := []struct {
		name        string
		resourceURI string
		path        string
		wantStatus  int
		wantMeta    bool
	}{
		{
			name:        "root-mounted serves the bare path",
			resourceURI: "https://grafana-mcp.example.com",
			path:        wellKnown,
			wantStatus:  http.StatusOK,
			wantMeta:    true,
		},
		{
			name:        "root-mounted 404s a suffix it does not serve",
			resourceURI: "https://grafana-mcp.example.com",
			path:        wellKnown + "/mcp",
			wantStatus:  http.StatusNotFound,
		},
		{
			name:        "root-mounted 404s the trailing-slash form",
			resourceURI: "https://grafana-mcp.example.com",
			path:        wellKnown + "/",
			wantStatus:  http.StatusNotFound,
		},
		{
			name:        "path-mounted serves the inserted form",
			resourceURI: "https://example.com/mcp",
			path:        wellKnown + "/mcp",
			wantStatus:  http.StatusOK,
			wantMeta:    true,
		},
		{
			name:        "path-mounted still serves the root form as fallback",
			resourceURI: "https://example.com/mcp",
			path:        wellKnown,
			wantStatus:  http.StatusOK,
			wantMeta:    true,
		},
		{
			name:        "path-mounted 404s a different suffix",
			resourceURI: "https://example.com/mcp",
			path:        wellKnown + "/other",
			wantStatus:  http.StatusNotFound,
		},
		{
			name:        "nested path-mounted resource",
			resourceURI: "https://example.com/public/mcp",
			path:        wellKnown + "/public/mcp",
			wantStatus:  http.StatusOK,
			wantMeta:    true,
		},
		{
			// No separator, so this is not part of the well-known subtree. It
			// belongs to the proxy, which means auth — a 401 challenge here is
			// the correct answer, and the assertion guards the prefix check
			// from being loosened to a bare HasPrefix.
			name:        "near-miss path is proxy traffic, not metadata",
			resourceURI: "https://grafana-mcp.example.com",
			path:        wellKnown + "XYZ",
			wantStatus:  http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwks := newTestJWKS(t)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
			cfg.resourceURI = tt.resourceURI
			result, cancel, _ := startRun(t, &cfg)
			defer cancel()

			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
				"http://"+result.Addr+tt.path, http.NoBody)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("GET %s: status = %d, want %d", tt.path, resp.StatusCode, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusNotFound {
				// The point of the change: a discovery probe gets a terminal
				// answer, not an invitation to authenticate.
				if ch := resp.Header.Get("WWW-Authenticate"); ch != "" {
					t.Errorf("GET %s: 404 carries a WWW-Authenticate challenge: %s", tt.path, ch)
				}
			}

			if tt.wantMeta {
				var meta map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
					t.Fatalf("decode metadata: %v", err)
				}
				if meta["resource"] != tt.resourceURI {
					t.Errorf("resource = %v, want %q", meta["resource"], tt.resourceURI)
				}
			}
		})
	}
}

// TestRun_WellKnownFormsServeIdenticalBytes asserts the root and path-inserted
// routes share one pre-marshaled document rather than rendering separately —
// two byte-different metadata documents for one resource would be a discovery
// hazard, since clients may reach either.
func TestRun_WellKnownFormsServeIdenticalBytes(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	cfg.resourceURI = "https://example.com/mcp"
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	get := func(path string) []byte {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
			"http://"+result.Addr+path, http.NoBody)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return body
	}

	root := get("/.well-known/oauth-protected-resource")
	inserted := get("/.well-known/oauth-protected-resource/mcp")

	if !bytes.Equal(root, inserted) {
		t.Errorf("the two well-known forms serve different documents:\n root: %s\n path: %s", root, inserted)
	}
}

// TestRun_OriginValidationDisabledByDefault is the assertion that matters most
// for this feature: with ALLOWED_ORIGINS unset — the production configuration —
// an Origin header changes nothing at all.
//
// If this ever fails, every browser-originated request to the live connector is
// being 403'd, and nothing else would tell us: /healthz is exempt and stays
// green, so the container stays healthy and deploy rollback never fires.
func TestRun_OriginValidationDisabledByDefault(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	if len(cfg.allowedOrigins) != 0 {
		t.Fatalf("test config should leave allowedOrigins empty, got %v", cfg.allowedOrigins)
	}
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	// An origin nobody would allow-list. Unauthenticated, so the expected
	// answer is the auth challenge — proving the request reached the auth
	// middleware rather than being cut off by an origin check.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost,
		fmt.Sprintf("http://%s/mcp", result.Addr), http.NoBody)
	req.Header.Set("Origin", "https://definitely-not-allowed.example")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("origin validation is active with ALLOWED_ORIGINS unset — it must be opt-in")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (request should reach auth untouched)", resp.StatusCode)
	}
}

// TestRun_OriginValidationEnabled exercises the configured path end to end,
// including the /healthz exemption that keeps a bad allow-list from taking the
// container down through its health check.
func TestRun_OriginValidationEnabled(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	cfg.allowedOrigins = []string{"https://claude.ai"}
	result, cancel, _ := startRun(t, &cfg)
	defer cancel()

	tests := []struct {
		name       string
		path       string
		originHdr  string
		wantStatus int
	}{
		// 401, not 200: these reach the auth middleware, which is the point.
		{"allowed origin reaches auth", "/mcp", "https://claude.ai", http.StatusUnauthorized},
		{"absent origin reaches auth", "/mcp", "", http.StatusUnauthorized},
		{"disallowed origin is blocked", "/mcp", "https://evil.example", http.StatusForbidden},
		{"suffix confusion is blocked", "/mcp", "https://claude.ai.evil.example", http.StatusForbidden},
		{"healthz is exempt", "/healthz", "https://evil.example", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
				fmt.Sprintf("http://%s%s", result.Addr, tt.path), http.NoBody)
			if tt.originHdr != "" {
				req.Header.Set("Origin", tt.originHdr)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			// Security headers wrap the origin guard, so even a 403 carries them.
			if resp.StatusCode == http.StatusForbidden {
				if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
					t.Errorf("403 missing security headers: X-Content-Type-Options = %q", got)
				}
			}
		})
	}
}

// --- Healthcheck subcommand tests ---

// TestHealthcheckURL covers the host-mapping branches that were untestable
// while the logic read LISTEN_ADDR from the environment directly.
func TestHealthcheckURL(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		want    string
		wantErr bool
	}{
		{"empty defaults to 0.0.0.0:8080", "", "http://localhost:8080/healthz", false},
		{"ipv4 wildcard maps to localhost", "0.0.0.0:8080", "http://localhost:8080/healthz", false},
		{"ipv6 wildcard maps to localhost", "[::]:8080", "http://localhost:8080/healthz", false},
		{"empty host maps to localhost", ":8080", "http://localhost:8080/healthz", false},
		{"loopback is dialed as-is", "127.0.0.1:9090", "http://127.0.0.1:9090/healthz", false},
		// The production bind address. Mapping this to localhost would make the
		// container healthcheck fail forever and trip a deploy rollback, so this
		// case is the regression healthcheckURL exists to protect.
		{"concrete IP is dialed as-is", "172.20.0.133:8080", "http://172.20.0.133:8080/healthz", false},
		// Proves net.JoinHostPort re-brackets the IPv6 literal SplitHostPort stripped.
		{"ipv6 literal is re-bracketed", "[fd00::1]:8080", "http://[fd00::1]:8080/healthz", false},
		{"missing port is an error", "no-port", "", true},
		{"too many colons is an error", "host:port:extra", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := healthcheckURL(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("healthcheckURL(%q) = %q, want error", tt.addr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("healthcheckURL(%q) returned error: %v", tt.addr, err)
			}
			if got != tt.want {
				t.Errorf("healthcheckURL(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// TestCheckHealth asserts the exit-code contract: 0 only on HTTP 200.
func TestCheckHealth(t *testing.T) {
	t.Run("200 exits 0", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		if got := checkHealth(srv.URL + "/healthz"); got != 0 {
			t.Errorf("checkHealth = %d, want 0", got)
		}
	})

	t.Run("500 exits 1", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		if got := checkHealth(srv.URL + "/healthz"); got != 1 {
			t.Errorf("checkHealth = %d, want 1", got)
		}
	})

	t.Run("unreachable exits 1", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		target := srv.URL + "/healthz"
		// Close before probing: the port is still bound to nothing, so the dial
		// fails with an immediate ECONNREFUSED rather than burning the client's
		// full 5s timeout the way an unroutable address would.
		srv.Close()

		if got := checkHealth(target); got != 1 {
			t.Errorf("checkHealth = %d, want 1", got)
		}
	})

	t.Run("malformed URL exits 1", func(t *testing.T) {
		// Unbalanced bracket fails in http.NewRequestWithContext, covering the
		// request-construction error arm before any dial is attempted.
		if got := checkHealth("http://[::1:8080/healthz"); got != 1 {
			t.Errorf("checkHealth = %d, want 1", got)
		}
	})
}

// TestRunHealthcheck_EnvWiring is the only test proving the CLI shell is still
// wired to LISTEN_ADDR. main() calls runHealthcheck for the "healthcheck"
// subcommand used by the Dockerfile HEALTHCHECK; a regression in this wiring
// would surface only after image build and deploy, as a rollback rather than
// a clear error.
func TestRunHealthcheck_EnvWiring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	listenAddr := strings.TrimPrefix(srv.URL, "http://")
	t.Setenv("LISTEN_ADDR", listenAddr)
	if got := runHealthcheck(); got != 0 {
		t.Errorf("runHealthcheck with healthy server = %d, want 0", got)
	}

	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	closedAddr := strings.TrimPrefix(closed.URL, "http://")
	closed.Close()

	t.Setenv("LISTEN_ADDR", closedAddr)
	if got := runHealthcheck(); got != 1 {
		t.Errorf("runHealthcheck with closed server = %d, want 1", got)
	}
}
