package origin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c-premus/mcp-gate/internal/origin"
)

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   []string
		want    []string
		wantErr bool
	}{
		{"empty means disabled", nil, nil, false},
		{"all-blank means disabled", []string{"", "  "}, nil, false},
		{"single origin", []string{"https://claude.ai"}, []string{"https://claude.ai"}, false},
		{
			name:  "multiple origins",
			input: []string{"https://claude.ai", "https://claude.com"},
			want:  []string{"https://claude.ai", "https://claude.com"},
		},
		{
			name:  "scheme and host are lowercased",
			input: []string{"HTTPS://Claude.AI"},
			want:  []string{"https://claude.ai"},
		},
		{
			// A port is part of the origin triple and is not normalized away:
			// https://example.com and https://example.com:443 are distinct, and
			// browsers omit the default port, so the operator must list the form
			// the client actually sends.
			name:  "explicit port is preserved",
			input: []string{"http://localhost:8080"},
			want:  []string{"http://localhost:8080"},
		},
		{
			name:  "trailing slash is tolerated",
			input: []string{"https://claude.ai/"},
			want:  []string{"https://claude.ai"},
		},

		// Rejections. Each of these is a plausible operator mistake that would
		// otherwise allow-list something they did not intend.
		{"null is refused", []string{"null"}, nil, true},
		{"NULL is refused case-insensitively", []string{"NULL"}, nil, true},
		{"null among valid entries is refused", []string{"https://claude.ai", "null"}, nil, true},
		{"bare hostname has no scheme", []string{"claude.ai"}, nil, true},
		{"scheme without host", []string{"https://"}, nil, true},
		{"a full URL is not an origin", []string{"https://claude.ai/api/mcp"}, nil, true},
		{"query string", []string{"https://claude.ai?a=b"}, nil, true},
		{"fragment", []string{"https://claude.ai#x"}, nil, true},
		{"userinfo", []string{"https://user:pass@claude.ai"}, nil, true},
		{"wildcard is not supported", []string{"*"}, nil, true},
		{
			// Refused loudly rather than accepted-and-never-matched: exact
			// matching means a wildcard entry silently allow-lists nothing.
			name:    "wildcard subdomain is refused",
			input:   []string{"https://*.claude.ai"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := origin.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%v) = %v, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%v): unexpected error: %v", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Parse(%v) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Parse(%v)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// newGuard returns a handler with Origin validation applied over a 200-OK
// terminal handler, plus a pointer that reports whether the request got through.
func newGuard(t *testing.T, allowed []string, exempt ...string) (handler http.Handler, reachedNext *bool) {
	t.Helper()
	var reached bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	parsed, err := origin.Parse(allowed)
	if err != nil {
		t.Fatalf("Parse(%v): %v", allowed, err)
	}
	return origin.Middleware(parsed, exempt...)(next), &reached
}

func TestMiddleware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		allowed    []string
		originHdr  string
		path       string
		exempt     []string
		wantStatus int
		wantReach  bool
	}{
		{
			// The default posture. Nothing configured, nothing enforced, and
			// the middleware returns next unchanged so it costs nothing.
			name:       "disabled by default",
			allowed:    nil,
			originHdr:  "https://evil.example",
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			// The spec's own carve-out: "if the Origin header is present and
			// invalid". Absent is not present. This is what keeps every
			// non-browser MCP client working.
			name:       "absent Origin is allowed",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "",
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "allowed origin passes",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "https://claude.ai",
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "case differences still match",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "HTTPS://Claude.AI",
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "second entry in the list matches",
			allowed:    []string{"https://claude.ai", "https://claude.com"},
			originHdr:  "https://claude.com",
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "disallowed origin is rejected",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			// The assertion that catches a naive HasPrefix implementation, and
			// the reason matching is exact equality on the canonical form.
			name:       "suffix confusion is rejected",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "https://claude.ai.evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			// And the reason it is not HasSuffix either.
			name:       "prefix confusion is rejected",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "https://evil-claude.ai",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "different scheme is a different origin",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "http://claude.ai",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "different port is a different origin",
			allowed:    []string{"http://localhost:8080"},
			originHdr:  "http://localhost:9090",
			wantStatus: http.StatusForbidden,
		},
		{
			// Parse refuses "null" in the allow-list, so nothing can match it.
			name:       "opaque origin is rejected",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "null",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unparseable origin is rejected",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "://not a url",
			wantStatus: http.StatusForbidden,
		},
		{
			// Header-splitting attempt. Go's server rejects control characters
			// in header values before we see them, but if one arrives it must
			// not canonicalize into a match.
			name:       "injection attempt is rejected",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "https://claude.ai\r\nX-Evil: 1",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "exempt path bypasses the check",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "https://evil.example",
			path:       "/healthz",
			exempt:     []string{"/healthz"},
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "exemption is exact, not a prefix",
			allowed:    []string{"https://claude.ai"},
			originHdr:  "https://evil.example",
			path:       "/healthz/sub",
			exempt:     []string{"/healthz"},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler, reached := newGuard(t, tt.allowed, tt.exempt...)

			path := tt.path
			if path == "" {
				path = "/mcp"
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, http.NoBody)
			if tt.originHdr != "" {
				// Direct map assignment: Header.Set would reject or mangle the
				// injection case before it reaches the middleware.
				req.Header["Origin"] = []string{tt.originHdr}
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if *reached != tt.wantReach {
				t.Errorf("reached next handler = %v, want %v", *reached, tt.wantReach)
			}
		})
	}
}

func TestMiddlewareRejectionBody(t *testing.T) {
	t.Parallel()
	handler, _ := newGuard(t, []string{"https://claude.ai"})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if body["error"] != "forbidden" {
		t.Errorf("error = %q, want forbidden", body["error"])
	}
	// The response must not echo the rejected origin or name the allow-list —
	// an unauthenticated caller learns only that it was refused.
	if strings.Contains(w.Body.String(), "evil.example") ||
		strings.Contains(w.Body.String(), "claude.ai") {
		t.Errorf("rejection body leaks origin details: %s", w.Body.String())
	}
}
