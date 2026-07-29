package metadata_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c-premus/mcp-gate/internal/metadata"
)

func mustHandler(t *testing.T, meta metadata.ProtectedResourceMetadata) http.HandlerFunc {
	t.Helper()
	h, err := metadata.Handler(meta)
	if err != nil {
		t.Fatalf("metadata.Handler: %v", err)
	}
	return h
}

func testMetadata() metadata.ProtectedResourceMetadata {
	return metadata.ProtectedResourceMetadata{
		Resource:               "https://mcp.example.com",
		AuthorizationServers:   []string{"https://auth.example.com/application/o/mcp/"},
		ScopesSupported:        []string{"openid", "profile"},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Grafana MCP Server",
		ResourceDocumentation:  "https://github.com/grafana/mcp-grafana",
	}
}

func TestHandler_GET_Returns200(t *testing.T) {
	t.Parallel()
	handler := mustHandler(t, testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandler_GET_ValidJSON(t *testing.T) {
	t.Parallel()
	handler := mustHandler(t, testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	var got metadata.ProtectedResourceMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Resource != "https://mcp.example.com" {
		t.Errorf("resource = %q, want %q", got.Resource, "https://mcp.example.com")
	}
	if len(got.AuthorizationServers) != 1 || got.AuthorizationServers[0] != "https://auth.example.com/application/o/mcp/" {
		t.Errorf("authorization_servers = %v, unexpected", got.AuthorizationServers)
	}
	if got.ResourceName != "Grafana MCP Server" {
		t.Errorf("resource_name = %q, want %q", got.ResourceName, "Grafana MCP Server")
	}
}

func TestHandler_GET_ContentType(t *testing.T) {
	t.Parallel()
	handler := mustHandler(t, testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestHandler_GET_CacheControl(t *testing.T) {
	t.Parallel()
	handler := mustHandler(t, testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if cc != "max-age=300, must-revalidate" {
		t.Errorf("Cache-Control = %q, want %q", cc, "max-age=300, must-revalidate")
	}
}

func TestHandler_POST_Returns405(t *testing.T) {
	t.Parallel()
	handler := mustHandler(t, testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandler_PUT_Returns405(t *testing.T) {
	t.Parallel()
	handler := mustHandler(t, testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandler_DELETE_Returns405(t *testing.T) {
	t.Parallel()
	handler := mustHandler(t, testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestURLFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		resourceURI string
		want        string
	}{
		{
			name:        "root-mounted resource",
			resourceURI: "https://mcp.example.com",
			want:        "https://mcp.example.com/.well-known/oauth-protected-resource",
		},
		{
			// A trailing slash must not produce a doubled separator.
			name:        "root-mounted with trailing slash",
			resourceURI: "https://mcp.example.com/",
			want:        "https://mcp.example.com/.well-known/oauth-protected-resource",
		},
		{
			// RFC 9728 §3.1 inserts the well-known segment between the
			// authority and the resource path — it does NOT append to it.
			name:        "path-mounted resource",
			resourceURI: "https://example.com/mcp",
			want:        "https://example.com/.well-known/oauth-protected-resource/mcp",
		},
		{
			name:        "nested path-mounted resource",
			resourceURI: "https://example.com/public/mcp",
			want:        "https://example.com/.well-known/oauth-protected-resource/public/mcp",
		},
		{
			name:        "non-default port is preserved",
			resourceURI: "https://mcp.example.com:8443",
			want:        "https://mcp.example.com:8443/.well-known/oauth-protected-resource",
		},
		{
			// Unreachable in practice (RESOURCE_URI is validated at startup),
			// but URLFor must stay total rather than panic or return "".
			name:        "unparseable input falls back to concatenation",
			resourceURI: "not-a-url",
			want:        "not-a-url/.well-known/oauth-protected-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := metadata.URLFor(tt.resourceURI); got != tt.want {
				t.Errorf("URLFor(%q) = %q, want %q", tt.resourceURI, got, tt.want)
			}
		})
	}
}

func TestPathSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		resourceURI string
		want        string
	}{
		{"root", "https://mcp.example.com", ""},
		{"root with trailing slash", "https://mcp.example.com/", ""},
		{"single segment", "https://example.com/mcp", "/mcp"},
		{"single segment with trailing slash", "https://example.com/mcp/", "/mcp"},
		{"nested", "https://example.com/public/mcp", "/public/mcp"},
		{"opaque input", "not-a-url", "not-a-url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := metadata.PathSuffix(tt.resourceURI); got != tt.want {
				t.Errorf("PathSuffix(%q) = %q, want %q", tt.resourceURI, got, tt.want)
			}
		})
	}
}
