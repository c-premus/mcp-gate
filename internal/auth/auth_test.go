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

	"github.com/chris/mcp-gate/internal/auth"
	"github.com/golang-jwt/jwt/v5"
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

	ctx, cancel := context.WithCancel(context.Background())
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
func signToken(t *testing.T, privKey *rsa.PrivateKey, kid string, claims jwt.Claims, headers ...map[string]any) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	for _, h := range headers {
		for k, v := range h {
			token.Header[k] = v
		}
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
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{testAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			ID:        "test-jti-123",
			Subject:   "test-user",
		},
		Scope: "openid profile",
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

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestValidToken(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	next := &nextHandler{}
	handler := mw.Handler(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
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
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMissingExp(t *testing.T) {
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
	token := signToken(t, ts.privKey, testKID, mapClaims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (missing exp must be rejected), got %d", w.Code)
	}
}

func TestWrongIssuer(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.Issuer = "https://evil.example.com"
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestWrongAudience(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	claims.Audience = jwt.ClaimStrings{"wrong-client"}
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHS256Rejected(t *testing.T) {
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
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid", "admin"})
	claims := validClaims()
	claims.Scope = "openid profile" // missing "admin"
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

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
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	// aud as single string (not array)
	claims := validClaims()
	claims.Audience = jwt.ClaimStrings{testAudience}
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (aud as string), got %d: %s", w.Code, w.Body.String())
	}
}

func TestAudAsArray(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	// aud as array with multiple values
	claims := validClaims()
	claims.Audience = jwt.ClaimStrings{testAudience, "other-audience"}
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (aud as array), got %d: %s", w.Code, w.Body.String())
	}
}

func TestFutureIatRejected(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	// iat 10 minutes in the future (well beyond 30s leeway)
	claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (future iat), got %d", w.Code)
	}
}

func TestFutureIatWithinLeeway(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	// iat 25 seconds in the future (within 30s leeway)
	claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(25 * time.Second))
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (iat within 30s leeway), got %d: %s", w.Code, w.Body.String())
	}
}

func TestTypAtJwtPasses(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "at+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestTypJWTDefaultPasses(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	// Default typ: "JWT" header (set by golang-jwt library)
	token := signToken(t, ts.privKey, testKID, claims)

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (typ JWT is standard default), got %d: %s", w.Code, w.Body.String())
	}
}

func TestTypWrongValueRejected(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	claims := validClaims()
	token := signToken(t, ts.privKey, testKID, claims, map[string]any{"typ": "id_token+jwt"})

	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (wrong typ), got %d", w.Code)
	}
}

func TestNoAuthorizationHeader(t *testing.T) {
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
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	w := doRequest(t, mw, "Token xyz")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIsReady(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	if !mw.IsReady() {
		t.Error("expected IsReady() to return true after successful JWKS fetch")
	}
}
