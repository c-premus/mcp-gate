package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/c-premus/mcp-gate/internal/auth"
	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// newStrictTypMiddleware is newMiddleware with StrictTyp enabled.
func newStrictTypMiddleware(t *testing.T, ts *testSetup) *auth.Middleware {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	mw, err := auth.NewMiddleware(auth.Config{
		Ctx:              ctx,
		JWKSURI:          ts.jwksServer.URL,
		RefreshInterval:  time.Hour,
		ExpectedIssuer:   testIssuer,
		ExpectedAudience: testAudience,
		RequiredScopes:   []string{"openid"},
		ResourceURI:      testResource,
		Realm:            testRealm,
		ScopesSupported:  "openid profile",
		StrictTyp:        true,
	})
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}
	return mw
}

// signWithoutTyp signs claims with the `typ` header removed entirely —
// golang-jwt sets `typ: JWT` by default, so signToken cannot express absence.
func signWithoutTyp(t *testing.T, ts *testSetup, claims jwt.Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID
	delete(token.Header, "typ")
	signed, err := token.SignedString(ts.privKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// TestTypHeaderAcceptance pins RFC 9068 §4's accepted `typ` values in both
// strictness modes. RFC 7515 §4.1.9 makes the `application/` prefix optional
// and the comparison case-insensitive, so `application/at+jwt` is the same
// type as `at+jwt` — it used to fall into the reject branch.
func TestTypHeaderAcceptance(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	lenient := newMiddleware(t, ts, []string{"openid"})
	strict := newStrictTypMiddleware(t, ts)

	tests := []struct {
		name       string
		typ        any // nil = header absent
		wantLaxOK  bool
		wantStrict bool
	}{
		{"at+jwt", "at+jwt", true, true},
		{"application/at+jwt", "application/at+jwt", true, true},
		{"case-insensitive", "Application/AT+JWT", true, true},
		{"JWT default", "JWT", true, false},
		{"empty", "", true, false},
		{"absent", nil, true, false},
		{"id token type", "id_token+jwt", false, false},
		{"non-string", 42, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var token string
			if tt.typ == nil {
				token = signWithoutTyp(t, ts, validClaims())
			} else {
				token = signToken(t, ts.privKey, validClaims(), map[string]any{"typ": tt.typ})
			}

			for _, mode := range []struct {
				name   string
				mw     *auth.Middleware
				wantOK bool
			}{
				{"lenient", lenient, tt.wantLaxOK},
				{"strict", strict, tt.wantStrict},
			} {
				w := doRequest(t, mode.mw, "Bearer "+token)
				wantStatus := http.StatusUnauthorized
				if mode.wantOK {
					wantStatus = http.StatusOK
				}
				if w.Code != wantStatus {
					t.Errorf("%s: status = %d, want %d", mode.name, w.Code, wantStatus)
				}
			}
		})
	}
}

// TestCritHeaderRejected pins RFC 7515 §4.1.11: a recipient MUST reject a JWS
// whose `crit` names an extension it does not understand. golang-jwt never
// reads `crit`, so without this check a signed token carrying it was accepted.
func TestCritHeaderRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})
	before := testutil.ToFloat64(metrics.AuthValidationsTotal.WithLabelValues("unsupported_crit"))

	token := signToken(t, ts.privKey, validClaims(), map[string]any{
		"typ":     "at+jwt",
		"crit":    []string{"exp-ext"},
		"exp-ext": true,
	})
	w := doRequest(t, mw, "Bearer "+token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", body["error"])
	}
	if got := testutil.ToFloat64(metrics.AuthValidationsTotal.WithLabelValues("unsupported_crit")); got <= before {
		t.Errorf("unsupported_crit counter did not increase (before %v, after %v)", before, got)
	}
}

// cnfClaims is validClaims plus an RFC 7800 confirmation claim.
type cnfClaims struct {
	auth.Claims
	Cnf any `json:"cnf,omitempty"`
}

// TestSenderConstrainedTokenRejected pins that a DPoP- or mTLS-bound token
// (one carrying `cnf`) is refused when presented as a plain bearer token:
// mcp-gate verifies neither proof, so accepting it would discard the binding.
func TestSenderConstrainedTokenRejected(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	tests := []struct {
		name   string
		cnf    any
		wantOK bool
	}{
		{"DPoP jkt", map[string]string{"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}, false},
		{"mTLS x5t#S256", map[string]string{"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}, false},
		{"absent", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := cnfClaims{Claims: validClaims(), Cnf: tt.cnf}
			token := signToken(t, ts.privKey, claims, map[string]any{"typ": "at+jwt"})
			w := doRequest(t, mw, "Bearer "+token)

			wantStatus := http.StatusUnauthorized
			if tt.wantOK {
				wantStatus = http.StatusOK
			}
			if w.Code != wantStatus {
				t.Errorf("status = %d, want %d", w.Code, wantStatus)
			}
		})
	}
}

// TestNonBearerSchemeIsNoToken pins the boundary of the new 400: a different
// scheme is "no bearer credentials" (401, bare challenge), not a malformed
// bearer request.
func TestNonBearerSchemeIsNoToken(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	defer ts.Close()

	mw := newMiddleware(t, ts, []string{"openid"})

	for _, header := range []string{"Basic dXNlcjpwYXNz", "DPoP abc", "Bearerfoo"} {
		w := doRequest(t, mw, header)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%q: status = %d, want 401", header, w.Code)
		}
		if w.Body.Len() != 0 {
			t.Errorf("%q: body = %q, want empty", header, w.Body.String())
		}
	}
}
