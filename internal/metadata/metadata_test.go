package metadata_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c-premus/mcp-gate/internal/metadata"
)

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
	handler := metadata.Handler(testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandler_GET_ValidJSON(t *testing.T) {
	handler := metadata.Handler(testMetadata())
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
	handler := metadata.Handler(testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestHandler_GET_CacheControl(t *testing.T) {
	handler := metadata.Handler(testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if cc != "max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", cc, "max-age=3600")
	}
}

func TestHandler_POST_Returns405(t *testing.T) {
	handler := metadata.Handler(testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandler_PUT_Returns405(t *testing.T) {
	handler := metadata.Handler(testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandler_DELETE_Returns405(t *testing.T) {
	handler := metadata.Handler(testMetadata())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/.well-known/oauth-protected-resource", http.NoBody)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
