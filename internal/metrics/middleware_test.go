package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRouteClassifier(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/.well-known/oauth-protected-resource", "metadata"},
		{"/healthz", "healthz"},
		{"/mcp", "proxy"},
		{"/mcp/v1", "proxy"},
		{"/anything", "proxy"},
		{"/", "proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, http.NoBody)
			if got := RouteClassifier(r); got != tt.want {
				t.Errorf("RouteClassifier(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestResponseRecorder_CapturesStatus(t *testing.T) {
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
	w := httptest.NewRecorder()
	rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	_, _ = rec.Write([]byte("hello"))
	if rec.statusCode != http.StatusOK {
		t.Errorf("statusCode = %d, want 200", rec.statusCode)
	}
}

func TestResponseRecorder_Flush(t *testing.T) {
	w := httptest.NewRecorder()
	rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	// Should not panic — httptest.ResponseRecorder implements Flusher
	rec.Flush()
}

func TestResponseRecorder_Unwrap(t *testing.T) {
	w := httptest.NewRecorder()
	rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	if rec.Unwrap() != w {
		t.Error("Unwrap() should return the underlying ResponseWriter")
	}
}

func TestMiddleware_RecordsMetrics(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

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
