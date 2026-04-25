package metrics

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// waitForListener polls the given TCP address until a connection succeeds or
// the deadline elapses. It replaces a fixed-duration sleep that flaked under
// CI load — a 50 ms wait is too long when the listener is already up and not
// long enough on a heavily loaded runner.
func waitForListener(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("listener at %s not reachable within %s", addr, timeout)
}

func TestNewServer_ListensAndServesMetrics(t *testing.T) {
	srv, err := NewServer(":0")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	waitForListener(t, srv.Addr(), time.Second)

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

	waitForListener(t, srv.Addr(), time.Second)

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
