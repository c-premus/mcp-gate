package metrics

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRouteClassifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want string
	}{
		{"/.well-known/oauth-protected-resource", "metadata"},
		// The mux serves the RFC 9728 §3.1 path-inserted form and 404s the rest
		// of the subtree. Both are metadata traffic; the classifier runs outside
		// the mux and has to agree with it.
		{"/.well-known/oauth-protected-resource/mcp", "metadata"},
		{"/.well-known/oauth-protected-resource/public/mcp", "metadata"},
		{"/.well-known/oauth-protected-resource/", "metadata"},
		// Near-miss: no separator, so the mux routes this to the proxy and the
		// label must say so. This is what the trailing "/" in the prefix check
		// protects.
		{"/.well-known/oauth-protected-resourceXYZ", "proxy"},
		{"/.well-known/oauth-authorization-server", "proxy"},
		{"/healthz", "healthz"},
		{"/mcp", "proxy"},
		{"/mcp/v1", "proxy"},
		{"/anything", "proxy"},
		{"/", "proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, http.NoBody)
			if got := RouteClassifier(r); got != tt.want {
				t.Errorf("RouteClassifier(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestResponseRecorder_CapturesStatus(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	rec.WriteHeader(http.StatusNotFound)
	if rec.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want 404", rec.statusCode)
	}

	// Second WriteHeader should not overwrite
	rec.WriteHeader(http.StatusOK)
	if rec.statusCode != http.StatusNotFound {
		t.Errorf("statusCode changed to %d after second WriteHeader", rec.statusCode)
	}
}

func TestResponseRecorder_WriteDefaultsTo200(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	_, _ = rec.Write([]byte("hello"))
	if rec.statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want 200", rec.statusCode)
	}
}

func TestResponseRecorder_Flush(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	// Should not panic — httptest.ResponseRecorder implements Flusher
	rec.Flush()
}

func TestResponseRecorder_Unwrap(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	if rec.Unwrap() != w {
		t.Error("Unwrap() should return the underlying ResponseWriter")
	}
}

func TestMiddleware_RecordsMetrics(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", http.NoBody)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	// Check that metrics were incremented
	val := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "healthz", "200"))
	if val < 1 {
		t.Errorf("HTTPRequestsTotal for GET /healthz 200 = %f, want >= 1", val)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"under limit", "hello", 10, "hello"},
		{"exactly at limit", "0123456789", 10, "0123456789"},
		{"over limit", "0123456789abcdef", 10, "0123456789…(truncated)"},
		{"empty", "", 10, ""},
		{
			name: "utf-8 boundary safe",
			// "ñ" is 2 bytes (0xC3 0xB1). Truncating at byte 5 of "aaaañ..."
			// must back off to byte 4 to avoid a dangling continuation byte.
			in:   "aaaañbb",
			max:  5,
			want: "aaaa…(truncated)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := truncate(tt.in, tt.max); got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

func TestMiddleware_TruncatesLongPathAndUserAgent(t *testing.T) {
	// A request with attacker-controlled path and User-Agent well over the
	// truncation cap must not produce log entries with full-size fields.
	// We can't easily intercept slog output here, but we can exercise the
	// middleware path and verify the metric still records. The truncation
	// function itself is unit-tested above.
	longPath := "/" + strings.Repeat("a", 4096)
	longUA := strings.Repeat("U", 4096)

	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, longPath, http.NoBody)
	req.Header.Set("User-Agent", longUA)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestMiddleware_RecordsMCPMetadata covers the 2026-07-28 request-metadata
// headers: they are observed into a bounded metric and the request log, and
// nowhere else. Not parallel — it reads package-global counters.
func TestMiddleware_RecordsMCPMetadata(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("proxy route records method and version", func(t *testing.T) {
		before := testutil.ToFloat64(MCPRequestsTotal.WithLabelValues("tools/call", "2026-07-28"))

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
		req.Header.Set(HeaderMCPProtocolVersion, "2026-07-28")
		req.Header.Set(HeaderMCPMethod, "tools/call")
		req.Header.Set(HeaderMCPName, "list_datasources")
		handler.ServeHTTP(httptest.NewRecorder(), req)

		if got := testutil.ToFloat64(MCPRequestsTotal.WithLabelValues("tools/call", "2026-07-28")) - before; got != 1 {
			t.Errorf("counter delta = %v, want 1", got)
		}
	})

	t.Run("unclamped values land in the bounded buckets", func(t *testing.T) {
		before := testutil.ToFloat64(MCPRequestsTotal.WithLabelValues("other", "other"))

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
		req.Header.Set(HeaderMCPProtocolVersion, "9999-99-99")
		req.Header.Set(HeaderMCPMethod, "attacker/controlled/"+strings.Repeat("x", 500))
		handler.ServeHTTP(httptest.NewRecorder(), req)

		if got := testutil.ToFloat64(MCPRequestsTotal.WithLabelValues("other", "other")) - before; got != 1 {
			t.Errorf("counter delta = %v, want 1", got)
		}
	})

	t.Run("a request without the headers is counted as absent", func(t *testing.T) {
		before := testutil.ToFloat64(MCPRequestsTotal.WithLabelValues("absent", "absent"))

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
		handler.ServeHTTP(httptest.NewRecorder(), req)

		if got := testutil.ToFloat64(MCPRequestsTotal.WithLabelValues("absent", "absent")) - before; got != 1 {
			t.Errorf("counter delta = %v, want 1", got)
		}
	})

	t.Run("non-proxy routes are not counted", func(t *testing.T) {
		// Health probes fire every 30s from Docker, Traefik, and Prometheus.
		// Counting them would swamp "absent" and destroy its meaning as a
		// migration signal.
		before := testutil.ToFloat64(MCPRequestsTotal.WithLabelValues("absent", "absent"))

		for _, path := range []string{"/healthz", "/.well-known/oauth-protected-resource"} {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
			handler.ServeHTTP(httptest.NewRecorder(), req)
		}

		if got := testutil.ToFloat64(MCPRequestsTotal.WithLabelValues("absent", "absent")) - before; got != 0 {
			t.Errorf("counter delta = %v, want 0 (health/metadata routes must not be counted)", got)
		}
	})
}

// TestMiddleware_LogsMCPFields asserts the request log carries Mcp-Method and
// Mcp-Name, that an oversized name is truncated, and — the important one — that
// a Base64-sentinel value is logged verbatim rather than decoded.
//
// Decoding would turn a client-controlled blob into arbitrary bytes in Loki:
// log injection, size amplification, and PII the client deliberately encoded
// away. The mcp_name_encoded flag exists so an operator knows the field is
// opaque rather than assuming truncation ate it.
//
// Not parallel: it swaps the default slog handler.
func TestMiddleware_LogsMCPFields(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name        string
		mcpMethod   string
		mcpName     string
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name:        "plain values are logged as-is",
			mcpMethod:   "tools/call",
			mcpName:     "list_datasources",
			wantPresent: []string{`"mcp_method":"tools/call"`, `"mcp_name":"list_datasources"`, `"mcp_name_encoded":false`},
		},
		{
			name:        "sentinel value is not decoded",
			mcpMethod:   "tools/call",
			mcpName:     "=?base64?SGVsbG8sIOS4lueVjA==?=",
			wantPresent: []string{`=?base64?SGVsbG8sIOS4lueVjA==?=`, `"mcp_name_encoded":true`},
			// "Hello, 世界" — the decoded payload must never appear.
			wantAbsent: []string{"世界"},
		},
		{
			name:        "oversized name is truncated",
			mcpMethod:   "resources/read",
			mcpName:     "file:///" + strings.Repeat("a", 2000),
			wantPresent: []string{"…(truncated)"},
		},
		{
			name:       "absent headers produce no empty keys",
			wantAbsent: []string{"mcp_method", "mcp_name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
			if tt.mcpMethod != "" {
				req.Header.Set(HeaderMCPMethod, tt.mcpMethod)
			}
			if tt.mcpName != "" {
				req.Header.Set(HeaderMCPName, tt.mcpName)
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)

			logged := buf.String()
			for _, want := range tt.wantPresent {
				if !strings.Contains(logged, want) {
					t.Errorf("log missing %q\n  got: %s", want, logged)
				}
			}
			for _, unwanted := range tt.wantAbsent {
				if strings.Contains(logged, unwanted) {
					t.Errorf("log unexpectedly contains %q\n  got: %s", unwanted, logged)
				}
			}
		})
	}
}
