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
func startRun(t *testing.T, cfg runConfig) (*runResult, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

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
	result, cancel, errCh := startRun(t, cfg)

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
	result, cancel, _ := startRun(t, cfg)
	defer cancel()

	resp, err := http.Get(fmt.Sprintf("http://%s/healthz", result.Addr))
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
	result, cancel, _ := startRun(t, cfg)
	defer cancel()

	resp, err := http.Get(fmt.Sprintf("http://%s/.well-known/oauth-protected-resource", result.Addr))
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
	result, cancel, _ := startRun(t, cfg)
	defer cancel()

	// Request without Authorization header should get 401
	resp, err := http.Get(fmt.Sprintf("http://%s/mcp", result.Addr))
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := run(ctx, cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("error = %q, want to contain 'invalid config'", err)
	}
}

func TestRun_BadJWKSURIFails(t *testing.T) {
	// Point JWKS at a closed server — should fail on init.
	ln, err := net.Listen("tcp", "localhost:0")
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err = run(ctx, cfg, nil)
	if err == nil {
		t.Fatal("expected error for unreachable JWKS URI")
	}
	if !strings.Contains(err.Error(), "auth middleware init") {
		t.Errorf("error = %q, want to contain 'auth middleware init'", err)
	}
}

func TestRun_XContentTypeOptionsOnAllRoutes(t *testing.T) {
	jwks := newTestJWKS(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := defaultTestConfig(jwks.server.URL, upstream.URL)
	result, cancel, _ := startRun(t, cfg)
	defer cancel()

	// nosniff should be on all routes: catch-all, healthz, and metadata.
	paths := []string{"/anything", "/healthz", "/.well-known/oauth-protected-resource"}
	for _, path := range paths {
		resp, err := http.Get(fmt.Sprintf("http://%s%s", result.Addr, path))
		if err != nil {
			t.Fatalf("request to %s failed: %v", path, err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options on %s = %q, want nosniff", path, got)
		}
	}
}
