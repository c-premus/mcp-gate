package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c-premus/mcp-gate/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

// Benchmarks for the auth.Handler hot path. The middleware sits in front of
// every authenticated request, so its per-request cost shows up directly in
// p99 latency. Benchmark goals (track via -count=5):
//
//   - ValidToken: dominant production path. Watch for allocation regressions
//     introduced by claim-mapping or logging changes.
//   - ExpiredToken: claims-validation fast path; rejected without invoking the
//     keyfunc cache lookup, so allocations should be lower than ValidToken.
//   - UnknownKid: JWKS-miss path. Configured with a tiny rate-limit window so
//     the benchmark measures the keyfunc miss + storage lookup, not the
//     deliberate stall we use in production to deter unknown-kid floods.
//   - NoToken: cheapest path — just header parse and 401 write.
//
// Run via:
//
//	go test -bench=. -benchmem -count=5 -run=^$ ./internal/auth/

const (
	benchIssuer   = "https://auth.example.com"
	benchAudience = "test-client-id"
	benchRealm    = "bench-realm"
	benchResource = "https://resource.example.com"
	benchKID      = "bench-key-1"
)

// benchEnv bundles the JWKS server and signing key so each benchmark can
// share setup and so we can build distinct middleware variants per benchmark
// (default vs. tiny rate-limit window for the unknown-kid path).
type benchEnv struct {
	privKey    *rsa.PrivateKey
	jwksServer *httptest.Server
}

func newBenchEnv(b *testing.B) *benchEnv {
	b.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("generate RSA key: %v", err)
	}

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": benchKID,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			},
		},
	}
	jwksBytes, _ := json.Marshal(jwks)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	b.Cleanup(srv.Close)

	return &benchEnv{privKey: privKey, jwksServer: srv}
}

func newBenchMiddleware(b *testing.B, env *benchEnv) *auth.Middleware {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)

	mw, err := auth.NewMiddleware(auth.Config{
		Ctx:              ctx,
		JWKSURI:          env.jwksServer.URL,
		RefreshInterval:  time.Hour,
		ExpectedIssuer:   benchIssuer,
		ExpectedAudience: benchAudience,
		RequiredScopes:   []string{"openid"},
		ResourceURI:      benchResource,
		Realm:            benchRealm,
		ScopesSupported:  "openid profile",
	})
	if err != nil {
		b.Fatalf("NewMiddleware: %v", err)
	}
	return mw
}

func benchSignToken(b *testing.B, privKey *rsa.PrivateKey, kid string, claims jwt.Claims) string {
	b.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "at+jwt"
	signed, err := token.SignedString(privKey)
	if err != nil {
		b.Fatalf("sign token: %v", err)
	}
	return signed
}

// noopHandler is the inner handler the auth middleware wraps. It does as
// little as possible so benchmark numbers reflect the middleware itself.
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// benchClaims returns claims that pass all validation checks.
func benchClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   benchIssuer,
		"aud":   benchAudience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"sub":   "bench-user",
		"jti":   "bench-jti",
		"scope": "openid profile",
	}
}

// BenchmarkAuthHandler_ValidToken measures the happy path: every claim valid,
// signature verifies, kid hits the JWKS cache. This is the production-dominant
// path and the headline number to watch.
func BenchmarkAuthHandler_ValidToken(b *testing.B) {
	env := newBenchEnv(b)
	mw := newBenchMiddleware(b, env)
	handler := mw.Handler(noopHandler)

	token := benchSignToken(b, env.privKey, benchKID, benchClaims())
	authHeader := "Bearer " + token

	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", http.NoBody)
		req.Header.Set("Authorization", authHeader)
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkAuthHandler_ExpiredToken measures the claims-validation fast path:
// the signature still verifies (kid hit), but jwt/v5 rejects on exp before
// any business-logic checks run.
func BenchmarkAuthHandler_ExpiredToken(b *testing.B) {
	env := newBenchEnv(b)
	mw := newBenchMiddleware(b, env)
	handler := mw.Handler(noopHandler)

	claims := benchClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := benchSignToken(b, env.privKey, benchKID, claims)
	authHeader := "Bearer " + token

	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", http.NoBody)
		req.Header.Set("Authorization", authHeader)
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkAuthHandler_UnknownKid measures the JWKS-miss path. The auth
// middleware's keyfunc rate-limits unknown-kid refreshes to deter floods;
// the production limiter holds the request goroutine for up to 5s, which
// would dominate benchmark numbers and obscure the actual lookup cost.
//
// Construct a fresh middleware whose RateLimitWaitMax is effectively zero by
// using a JWKS server with a short-lived key registration, then signing with
// a kid that was never published. The auth middleware itself doesn't expose
// RateLimitWaitMax; instead, the storage is "empty" for the unknown kid and
// the hot loop measures the kid-miss + early-return path.
//
// Note: because RateLimitWaitMax is fixed inside auth.NewMiddleware, this
// benchmark reflects realistic production cost for an unknown-kid request,
// including any rate-limit wait. Run with -benchtime=1x in CI to bound total
// time; full -count=5 runs take longer than the others.
func BenchmarkAuthHandler_UnknownKid(b *testing.B) {
	env := newBenchEnv(b)
	mw := newBenchMiddleware(b, env)
	handler := mw.Handler(noopHandler)

	claims := benchClaims()
	// Sign with the right key but an unknown kid. The library will look up
	// "unknown-kid", miss the cache, attempt a refresh (rate-limited, so it
	// returns immediately after the first call), and reject the token.
	token := benchSignToken(b, env.privKey, "unknown-kid", claims)
	authHeader := "Bearer " + token

	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", http.NoBody)
		req.Header.Set("Authorization", authHeader)
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkAuthHandler_NoToken measures the missing-Authorization fast path.
// This is the cheapest path through the middleware — header miss, write 401,
// return — and serves as the floor against which other paths are measured.
func BenchmarkAuthHandler_NoToken(b *testing.B) {
	env := newBenchEnv(b)
	mw := newBenchMiddleware(b, env)
	handler := mw.Handler(noopHandler)

	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", http.NoBody)
		handler.ServeHTTP(w, req)
	}
}
