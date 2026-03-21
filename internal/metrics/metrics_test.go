package metrics

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewServer_ListensAndServesMetrics(t *testing.T) {
	srv, err := NewServer(":0")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	// Wait briefly for server to start
	time.Sleep(50 * time.Millisecond)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+srv.Addr()+"/metrics", http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "go_goroutines") {
		t.Error("/metrics should contain go runtime metrics")
	}
}

func TestNewServer_HealthEndpoint(t *testing.T) {
	srv, err := NewServer(":0")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	time.Sleep(50 * time.Millisecond)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+srv.Addr()+"/healthz", http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
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

func TestNewServer_InvalidAddr(t *testing.T) {
	_, err := NewServer("invalid-no-port")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}
