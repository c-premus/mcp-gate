package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c-premus/mcp-gate/internal/auth"
	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	testIssuer   = "https://auth.example.com"
	testAudience = "test-client-id"
	testRealm    = "test-realm"
	testResource = "https://resource.example.com"
	testKID      = "test-key-1"
)

// testSetup holds shared test infrastructure.
type testSetup struct {
	privKey    *rsa.PrivateKey
	jwksServer *httptest.Server
}

func (ts *testSetup) Close() {
	ts.jwksServer.Close()
}

// newTestSetup creates an RSA key pair and a JWKS server serving its public key.
func newTestSetup(t *testing.T) *testSetup {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// Build JWKS JSON
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": testKID,
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

	return &testSetup{
		privKey:    privKey,
		jwksServer: srv,
	}
}

// base64URLUint encodes a big.Int to unpadded base64url.
func base64URLUint(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// newMiddleware creates an auth.Middleware connected to the test JWKS server.
func newMiddleware(t *testing.T, ts *testSetup, scopes []string) *auth.Middleware {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	mw, err := auth.NewMiddleware(auth.Config{
		Ctx:              ctx,
		JWKSURI:          ts.jwksServer.URL,
		RefreshInterval:  time.Hour,
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testAudience,
		RequiredScopes:   scopes,
		ResourceURI:      testResource,
		Realm:            testRealm,
		ScopesSupported:  "openid profile",
	})
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}
	return mw
}

// signToken creates a signed JWT string.
func signToken(t *testing.T, privKey *rsa.PrivateKey, claims jwt.Claims, headers ...map[string]any) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID
	for _, h := range headers {
		maps.Copy(token.Header, h)
	}

	signed, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// validClaims returns claims that pass all validation checks.
func validClaims() auth.Claims {
	now := time.Now()
	return auth.Claims{
		Issuer:    testIssuer,
		Audience:  jwt.ClaimStrings{testAudience},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		ID:        "test-jti-123",
		Subject:   "test-user",
		Scope:     auth.Scopes{"openid", "profile"},
	}
}

// nextHandler is a simple handler that records it was called.
type nextHandler struct {
	called bool
}

func (h *nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	w.WriteHeader(http.StatusOK)
}

// doRequest sends a request through the auth middleware and returns the response.
func doRequest(t *testing.T, mw *auth.Middleware, authHeader string) *httptest.ResponseRecorder {
	t.Helper()

	next := &nextHandler{}
	handler := mw.Handler(next)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestValidToken(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	next := &nextHandler{}
	handler := mw.Handler(next)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !next.called {
		t.Error("next handler was not called")
	}
}

func TestExpiredToken(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMissingExp(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	// Use MapClaims to omit exp entirely
	mapClaims := jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"iat":   time.Now().Unix(),
		"scope": "openid profile",
	}
	token := signToken(t, ts.privKey, mapClaims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (missing exp must be rejected), got %d", w.Code)
	}
}

func TestWrongIssuer(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.Issuer = "https://evil.example.com"
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestWrongAudience(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.Audience = jwt.ClaimStrings{"wrong-client"}
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHS256Rejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	// Sign with HMAC instead of RSA
	claims := jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "openid profile",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("symmetric-secret"))
	if err != nil {
		t.Fatalf("sign HS256 token: %v", err)
	}

	w := doRequest(t, mw, "Bearer "+signed)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (HS256 must be rejected), got %d", w.Code)
	}
}

func TestAlgNoneRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	// Craft a token with alg:none
	claims := jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "openid profile",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}

	w := doRequest(t, mw, "Bearer "+signed)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (alg:none must be rejected), got %d", w.Code)
	}
}

func TestMissingScopeReturns403(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid", "admin"})
	claims := validClaims()
	claims.Scope = auth.Scopes{"openid", "profile"} // missing "admin"
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (not 401) for insufficient scope, got %d", w.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "insufficient_scope" {
		t.Errorf("error = %q, want insufficient_scope", body["error"])
	}
}

func TestAudAsString(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	// aud as single string (not array)
	claims := validClaims()
	claims.Audience = jwt.ClaimStrings{testAudience}
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (aud as string), got %d: %s", w.Code, w.Body.String())
	}
}

func TestAudAsArray(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	// aud as array with multiple values
	claims := validClaims()
	claims.Audience = jwt.ClaimStrings{testAudience, "other-audience"}
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (aud as array), got %d: %s", w.Code, w.Body.String())
	}
}

func TestFutureIatRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	// iat 10 minutes in the future (well beyond 30s leeway)
	claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (future iat), got %d", w.Code)
	}
}

func TestFutureIatWithinLeeway(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	// iat 25 seconds in the future (within 30s leeway)
	claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(25 * time.Second))
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (iat within 30s leeway), got %d: %s", w.Code, w.Body.String())
	}
}

func TestTypAtJwtPasses(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestTypJWTDefaultPasses(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	// Default typ: "JWT" header (set by golang-jwt library)
	token := signToken(t, ts.privKey, claims)

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (typ JWT is standard default), got %d: %s", w.Code, w.Body.String())
	}
}

func TestTypWrongValueRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "id_token+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (wrong typ), got %d", w.Code)
	}
}

func TestNoAuthorizationHeader(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	w := doRequest(t, mw, "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("missing WWW-Authenticate header")
	}

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "unauthorized" {
		t.Errorf("error = %q, want unauthorized", body["error"])
	}
}

func TestMalformedBearer(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	w := doRequest(t, mw, "Token xyz")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIsReady(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	if !mw.IsReady(t.Context()) {
		t.Error("expected IsReady() to return true after successful JWKS fetch")
	}
}

func TestJWKSMetricsPrimedOnStartup(t *testing.T) {
	// NewMiddleware should prime the JWKS metrics on successful startup:
	// the key-count gauge should be non-zero and the last-key-change
	// timestamp should be roughly "now".
	ts := newTestSetup(t)
	defer ts.Close()

	before := time.Now().Unix()
	_ = newMiddleware(t, ts, []string{"openid"})
	after := time.Now().Unix()

	keyCount := testutil.ToFloat64(metrics.JWKSKeysLoaded)
	if keyCount < 1 {
		t.Errorf("JWKSKeysLoaded = %f, want >= 1 after startup", keyCount)
	}

	ts2 := testutil.ToFloat64(metrics.JWKSLastKeyChangeTimestamp)
	if ts2 < float64(before) || ts2 > float64(after)+1 {
		t.Errorf("JWKSLastKeyChangeTimestamp = %f, want in [%d, %d]", ts2, before, after)
	}
}

func TestEmptyBearerToken(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	// "Bearer " with nothing after the space — tests the token=="" branch
	w := doRequest(t, mw, "Bearer ")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "unauthorized" {
		t.Errorf("error = %q, want unauthorized", body["error"])
	}
}

// --- Security audit tests ---

func TestFutureNbfRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	// nbf 10 minutes in the future (well beyond 30s leeway)
	claims.NotBefore = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (future nbf beyond leeway), got %d", w.Code)
	}
}

func TestFutureNbfWithinLeeway(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	// nbf 25 seconds in the future (within 30s leeway)
	claims.NotBefore = jwt.NewNumericDate(time.Now().Add(25 * time.Second))
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (nbf within 30s leeway), got %d: %s", w.Code, w.Body.String())
	}
}

func TestMissingNbfAccepted(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	// Use MapClaims to omit nbf entirely — should be accepted since many
	// providers (including Authentik) do not include nbf in access tokens.
	mapClaims := jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"sub":   "test-user",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "openid profile",
	}
	token := signToken(t, ts.privKey, mapClaims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (missing nbf should be accepted), got %d: %s", w.Code, w.Body.String())
	}
}

// TestScopesUnmarshalJSON exercises the low-level wire-form handling of the
// Scopes type directly, including edge cases (null, invalid types) that the
// JWT-level integration tests don't hit.
func TestScopesUnmarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    auth.Scopes
		wantErr bool
	}{
		{name: "json array", input: `["openid","profile"]`, want: auth.Scopes{"openid", "profile"}},
		{name: "space-separated string", input: `"openid profile"`, want: auth.Scopes{"openid", "profile"}},
		{name: "single scope string", input: `"openid"`, want: auth.Scopes{"openid"}},
		{name: "empty array", input: `[]`, want: auth.Scopes{}},
		{name: "empty string", input: `""`, want: auth.Scopes{}},
		{name: "whitespace-only string", input: `"   "`, want: auth.Scopes{}},
		{name: "null", input: `null`, want: nil},
		{name: "number rejected", input: `42`, wantErr: true},
		{name: "object rejected", input: `{"scope":"openid"}`, wantErr: true},
		{name: "malformed rejected", input: `[`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got auth.Scopes
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("input %q: expected error, got nil (parsed as %v)", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("input %q: unexpected error: %v", tt.input, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("input %q: got %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestScopesMarshalJSON verifies that Scopes serializes to the RFC 6749
// space-separated string form on output, regardless of how it was populated.
func TestScopesMarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input auth.Scopes
		want  string
	}{
		{name: "two scopes", input: auth.Scopes{"openid", "profile"}, want: `"openid profile"`},
		{name: "single scope", input: auth.Scopes{"openid"}, want: `"openid"`},
		{name: "empty", input: auth.Scopes{}, want: `""`},
		{name: "nil", input: nil, want: `""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// TestScopeClaimAsJSONArray covers providers (e.g. Cloudflare Access) that emit
// the OAuth `scope` claim as a JSON array instead of the RFC 6749 space-separated
// string form. See GitHub issue #1.
func TestScopeClaimAsJSONArray(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	now := time.Now()
	mapClaims := jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"sub":   "test-user",
		"scope": []string{"openid", "profile"},
	}
	token := signToken(t, ts.privKey, mapClaims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for array-form scope, got %d: %s", w.Code, w.Body.String())
	}
}

// TestScopeClaimAsSpaceSeparatedString covers the RFC 6749 string form emitted
// by Authentik and most OIDC providers.
func TestScopeClaimAsSpaceSeparatedString(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	now := time.Now()
	mapClaims := jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"sub":   "test-user",
		"scope": "openid profile",
	}
	token := signToken(t, ts.privKey, mapClaims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for string-form scope, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEmptyScopeRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.Scope = nil // empty scope when openid is required
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (empty scope), got %d", w.Code)
	}
}

func TestUnknownKidRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	// Generate a different RSA key (not in JWKS)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	claims := validClaims()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "unknown-key-id"
	token.Header["typ"] = "at+jwt"
	signed, err := token.SignedString(otherKey)
	if err != nil {
		t.Fatalf("sign with other key: %v", err)
	}

	w := doRequest(t, mw, "Bearer "+signed)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (unknown kid), got %d", w.Code)
	}
}

// TestJWTErrorClassificationStable asserts that expired, wrong-audience,
// wrong-issuer, and malformed tokens produce distinct Warn log categories
// and never reflect raw token bytes. We don't need to intercept slog here:
// the invariant is that the middleware returns 401 with no raw error
// surface to the client. This test pins the absence of token bytes in the
// response body across four common error classes.
func TestJWTErrorClassificationStable(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()
	mw := newMiddleware(t, ts, []string{"openid"})

	tamperedBase64 := "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LTEiLCJ0eXAiOiJhdCtqd3QifQ.NOTVALIDBASE64!!!"

	tests := []struct {
		name    string
		builder func() string
	}{
		{
			name: "expired",
			builder: func() string {
				claims := validClaims()
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
				return signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})
			},
		},
		{
			name: "wrong_audience",
			builder: func() string {
				claims := validClaims()
				claims.Audience = jwt.ClaimStrings{"some-other-client"}
				return signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})
			},
		},
		{
			name: "wrong_issuer",
			builder: func() string {
				claims := validClaims()
				claims.Issuer = "https://attacker.example/"
				return signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})
			},
		},
		{
			name:    "malformed_base64",
			builder: func() string { return tamperedBase64 },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := doRequest(t, mw, "Bearer "+tc.builder())
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			// The response body must not include token bytes or raw jwt
			// error strings — the classifier strips those.
			body := w.Body.String()
			if strings.Contains(body, tamperedBase64) || strings.Contains(body, "eyJ") {
				t.Errorf("response body contains token material: %s", body)
			}
			if strings.Contains(body, "cannot unmarshal") {
				t.Errorf("response body leaks jwt/v5 parse detail: %s", body)
			}
		})
	}
}

// TestSignatureForgeryWithKnownKID asserts that a token signed by an attacker's
// key but advertising the cached `kid` of the JWKS's real key is rejected. This
// is the more adversarial cousin of TestUnknownKidRejected: instead of hoping
// to trigger a JWKS refresh by claiming a novel kid, the attacker reuses the
// known cached kid so the signature check is the only gate. Signature verify
// must fail; no other path should admit the token.
func TestSignatureForgeryWithKnownKID(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	claims := validClaims()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID // Known kid — matches the cached JWKS entry
	token.Header["typ"] = "at+jwt"
	signed, err := token.SignedString(attackerKey)
	if err != nil {
		t.Fatalf("sign with attacker key: %v", err)
	}

	w := doRequest(t, mw, "Bearer "+signed)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for signature forgery with known kid, got %d", w.Code)
	}
}

func TestLargeTokenRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	// Send a 500KB garbage token — should get 401, not hang or OOM
	largeToken := "Bearer " + strings.Repeat("a", 500_000)
	w := doRequest(t, mw, largeToken)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for large garbage token, got %d", w.Code)
	}
}

// TestMalformedJWKSResponse asserts mcp-gate's behavior when the JWKS endpoint
// returns a well-formed JSON object that lacks the `keys` array. Two outcomes
// are both acceptable for safety — either path must gate traffic at /healthz:
//
//   - NewMiddleware returns an error (initialization fails, container never
//     becomes healthy, Traefik keeps old instance).
//   - NewMiddleware succeeds with zero keys loaded; IsReady must then return
//     false so /healthz responds 503 until keys actually load.
//
// The prior version of this test asserted neither outcome.
func TestMalformedJWKSResponse(t *testing.T) {
	t.Parallel()
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"not": "jwks"}`))
	}))
	defer badServer.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	mw, err := auth.NewMiddleware(auth.Config{
		Ctx:              ctx,
		JWKSURI:          badServer.URL,
		RefreshInterval:  time.Hour,
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testAudience,
		RequiredScopes:   []string{"openid"},
		ResourceURI:      testResource,
		Realm:            testRealm,
		ScopesSupported:  "openid profile",
	})

	if err != nil {
		// Path 1: initialization refused. Safe.
		return
	}

	// Path 2: initialization succeeded with zero keys. IsReady MUST refuse so
	// /healthz stays 503 until real keys load.
	if mw.IsReady(ctx) {
		t.Fatal("IsReady returned true despite JWKS having no valid keys; /healthz would serve 200 with an empty keyset")
	}
}

func TestErrorResponseNoInternalDetails(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	body := w.Body.String()
	// Response must not leak JWKS URI, key IDs, or JWT library error strings
	if strings.Contains(body, ts.jwksServer.URL) {
		t.Errorf("error body leaks JWKS URI: %s", body)
	}
	if strings.Contains(body, testKID) {
		t.Errorf("error body leaks key ID: %s", body)
	}
	// The generic description "invalid or expired" is fine — ensure the specific
	// library error strings are not leaked (e.g., "token is expired", parse errors)
	if strings.Contains(body, "token is expired") {
		t.Errorf("error body leaks specific JWT library error: %s", body)
	}
	if strings.Contains(body, "token is malformed") {
		t.Errorf("error body leaks JWT parse error: %s", body)
	}
	if strings.Contains(body, "keyfunc") {
		t.Errorf("error body leaks JWKS implementation detail: %s", body)
	}
}

func TestMissingSubjectRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	// Use MapClaims to omit sub entirely
	mapClaims := jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "openid profile",
	}
	token := signToken(t, ts.privKey, mapClaims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (missing sub), got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", body["error"])
	}
}

func TestEmptySubjectRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.Subject = ""
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (empty sub), got %d: %s", w.Code, w.Body.String())
	}
}

func TestRS384Rejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()

	// Sign with RS384 instead of RS256 — must be rejected
	token := jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
	token.Header["kid"] = testKID
	token.Header["typ"] = "at+jwt"
	signed, err := token.SignedString(ts.privKey)
	if err != nil {
		t.Fatalf("sign RS384 token: %v", err)
	}

	w := doRequest(t, mw, "Bearer "+signed)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (RS384 must be rejected), got %d", w.Code)
	}
}

func TestEmptyRequiredScopesAcceptsAnyScope(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	// No required scopes — any token should pass scope check
	mw := newMiddleware(t, ts, nil)
	claims := validClaims()
	claims.Scope = nil // no scope at all
	token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (empty RequiredScopes means no scope enforcement), got %d: %s", w.Code, w.Body.String())
	}
}

func TestNewMiddleware_MissingJWKSURI(t *testing.T) {
	t.Parallel()
	_, err := auth.NewMiddleware(auth.Config{
		Ctx:              t.Context(),
		JWKSURI:          "",
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testAudience,
	})
	if err == nil {
		t.Fatal("expected error for empty JWKSURI")
	}
	if !strings.Contains(err.Error(), "JWKSURI") {
		t.Errorf("error %q should mention JWKSURI", err)
	}
}

func TestNewMiddleware_MissingExpectedIssuer(t *testing.T) {
	t.Parallel()
	_, err := auth.NewMiddleware(auth.Config{
		Ctx:              t.Context(),
		JWKSURI:          "https://example.com/jwks",
		ExpectedIssuer:   "",
		ExpectedAudience: testAudience,
	})
	if err == nil {
		t.Fatal("expected error for empty ExpectedIssuer")
	}
	if !strings.Contains(err.Error(), "ExpectedIssuer") {
		t.Errorf("error %q should mention ExpectedIssuer", err)
	}
}

func TestNewMiddleware_MissingExpectedAudience(t *testing.T) {
	t.Parallel()
	_, err := auth.NewMiddleware(auth.Config{
		Ctx:              t.Context(),
		JWKSURI:          "https://example.com/jwks",
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: "",
	})
	if err == nil {
		t.Fatal("expected error for empty ExpectedAudience")
	}
	if !strings.Contains(err.Error(), "ExpectedAudience") {
		t.Errorf("error %q should mention ExpectedAudience", err)
	}
}

func TestMultipleAuthorizationHeaders(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	next := &nextHandler{}
	handler := mw.Handler(next)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	// Add multiple Authorization headers
	req.Header.Add("Authorization", "Bearer token1")
	req.Header.Add("Authorization", "Bearer token2")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should reject — first header value is "token1" which is invalid
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for multiple auth headers, got %d", w.Code)
	}
}

// mutableJWKSServer serves a JWKS whose body and status can be swapped at
// runtime. The zero value is unusable; construct via newMutableJWKS().
type mutableJWKSServer struct {
	server *httptest.Server
	mu     sync.Mutex
	body   []byte
	status int
	fail   atomic.Bool // when true, respond 500 regardless of body
}

func newMutableJWKS(t *testing.T, initial []byte) *mutableJWKSServer {
	t.Helper()
	m := &mutableJWKSServer{body: initial, status: http.StatusOK}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if m.fail.Load() {
			http.Error(w, "simulated JWKS outage", http.StatusInternalServerError)
			return
		}
		m.mu.Lock()
		body, status := m.body, m.status
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mutableJWKSServer) swap(body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.body = body
}

// jwksBodyForKey builds a JWKS JSON body exposing a single RSA public key.
func jwksBodyForKey(t *testing.T, kid string, key *rsa.PrivateKey) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64URLUint(key.N),
				"e":   base64URLUint(big.NewInt(int64(key.E))),
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// waitForMetric polls a metric reader every 50ms until cond returns true or
// the deadline elapses. Reports the final observed value in the failure
// message so flake diagnosis doesn't require re-running.
func waitForMetric(t *testing.T, reader func() float64, cond func(v float64) bool, timeout time.Duration, label string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last float64
	for time.Now().Before(deadline) {
		last = reader()
		if cond(last) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: condition not met within %s (last value %f)", label, timeout, last)
}

// TestPollJWKSDetectsKeyRotation asserts that when the JWKS key set changes
// (kid rotation), the polling goroutine detects the new fingerprint and
// bumps JWKSLastKeyChangeTimestamp. This is the correctness signal the
// mcp-gate-jwks-keys-stale alert depends on.
func TestPollJWKSDetectsKeyRotation(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen keyA: %v", err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen keyB: %v", err)
	}

	jwks := newMutableJWKS(t, jwksBodyForKey(t, "rot-kid-1", keyA))

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	// Short RefreshInterval drives frequent library refresh; pollInterval
	// derives to ~100ms (min(200ms/2, 5m)) so the poll sees the new fingerprint
	// within a second of the swap.
	_, err = auth.NewMiddleware(auth.Config{
		Ctx:              ctx,
		JWKSURI:          jwks.server.URL,
		RefreshInterval:  200 * time.Millisecond,
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testAudience,
		RequiredScopes:   []string{"openid"},
		ResourceURI:      testResource,
		Realm:            testRealm,
		ScopesSupported:  "openid profile",
	})
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	initial := testutil.ToFloat64(metrics.JWKSLastKeyChangeTimestamp)

	// Ensure enough wall-clock passes that a bump to time.Now().Unix() is
	// strictly greater than `initial` at 1-second resolution.
	time.Sleep(1100 * time.Millisecond)

	jwks.swap(jwksBodyForKey(t, "rot-kid-2", keyB))

	waitForMetric(t,
		func() float64 { return testutil.ToFloat64(metrics.JWKSLastKeyChangeTimestamp) },
		func(v float64) bool { return v > initial },
		5*time.Second,
		"JWKSLastKeyChangeTimestamp did not advance after kid swap")
}

// TestJWKSRefreshErrorIncrementsCounter asserts that the jwkset library's
// RefreshErrorHandler wired up in auth.NewMiddleware actually reaches the
// mcpgate_jwks_refresh_errors_total counter. This is the PRIMARY liveness
// signal for JWKS health — if it doesn't increment on failure, the
// mcp-gate-jwks-refresh-errors alert never fires.
func TestJWKSRefreshErrorIncrementsCounter(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	jwks := newMutableJWKS(t, jwksBodyForKey(t, "err-kid", key))

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	before := testutil.ToFloat64(metrics.JWKSRefreshErrorsTotal)

	_, err = auth.NewMiddleware(auth.Config{
		Ctx:              ctx,
		JWKSURI:          jwks.server.URL,
		RefreshInterval:  200 * time.Millisecond,
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testAudience,
		RequiredScopes:   []string{"openid"},
		ResourceURI:      testResource,
		Realm:            testRealm,
		ScopesSupported:  "openid profile",
	})
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}

	// Flip the JWKS to 500 AFTER initial fetch succeeded, so NewMiddleware
	// doesn't error at startup. The library's refresh goroutine will hit 500
	// on the next tick.
	jwks.fail.Store(true)

	waitForMetric(t,
		func() float64 { return testutil.ToFloat64(metrics.JWKSRefreshErrorsTotal) },
		func(v float64) bool { return v > before },
		5*time.Second,
		"JWKSRefreshErrorsTotal did not increment after JWKS endpoint began returning 500")
}

// TestChallengeShape pins the structure of all three WWW-Authenticate
// challenges in one place. The individual challenge tests elsewhere in this
// file deliberately assert only substrings or response bodies, so before this
// test a format change could silently drop resource_metadata — the parameter
// the MCP authorization flow opens with — and nothing would fail.
//
// It asserts parameter presence, not the full challenge string. An exact-match
// assertion would have to be updated on every wording change and would provoke
// exactly the "just update the expected string" reflex that makes a regression
// test worthless.
func TestChallengeShape(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid", "admin"})

	// A token that is valid but lacks the "admin" scope, to reach the 403 path.
	insufficientClaims := validClaims()
	insufficientClaims.Scope = auth.Scopes{"openid"}

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
		wantParams []string
		wantScope  string
	}{
		{
			name:       "no token",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			// RFC 6750 §3.1: no error code when the request lacks credentials.
			wantParams: []string{`realm="`, `resource_metadata="`},
			// Advertises what to request, since the client has nothing yet.
			wantScope: `scope="openid profile"`,
		},
		{
			name:       "invalid token",
			authHeader: "Bearer not.a.jwt",
			wantStatus: http.StatusUnauthorized,
			wantParams: []string{`realm="`, `error="invalid_token"`, `resource_metadata="`},
			// Like the no-token challenge, and for the same reason: the client
			// is about to start a fresh authorization and needs to know what to
			// request. Contrast the 403, which names what is missing.
			wantScope: `scope="openid profile"`,
		},
		{
			name:       "insufficient scope",
			authHeader: "Bearer " + signToken(t, ts.privKey, insufficientClaims),
			wantStatus: http.StatusForbidden,
			wantParams: []string{`realm="`, `error="insufficient_scope"`, `resource_metadata="`},
			// Names what is missing, so the client can step up.
			wantScope: `scope="openid admin"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := doRequest(t, mw, tt.authHeader)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			challenge := w.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, "Bearer ") {
				t.Fatalf("challenge = %q, want a Bearer challenge", challenge)
			}
			for _, param := range tt.wantParams {
				if !strings.Contains(challenge, param) {
					t.Errorf("challenge missing %s\n  got: %s", param, challenge)
				}
			}
			if tt.wantScope != "" && !strings.Contains(challenge, tt.wantScope) {
				t.Errorf("challenge missing %s\n  got: %s", tt.wantScope, challenge)
			}

			// resource_metadata must be the RFC 9728 well-known URL derived
			// from ResourceURI, not the bare resource URI.
			wantMetadata := `resource_metadata="` + testResource + `/.well-known/oauth-protected-resource"`
			if !strings.Contains(challenge, wantMetadata) {
				t.Errorf("challenge resource_metadata wrong\n  want substring: %s\n  got: %s", wantMetadata, challenge)
			}
		})
	}
}
