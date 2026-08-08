package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetup_NoOpWhenEndpointEmpty(t *testing.T) {
	provider, err := Setup(context.Background(), Config{
		Endpoint:    "",
		ServiceName: "test",
		SampleRate:  1.0,
		Version:     "test",
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if provider.tp != nil {
		t.Error("expected nil TracerProvider for empty endpoint")
	}

	// Shutdown should be safe on no-op provider
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown on no-op: %v", err)
	}
}

func TestTracesEndpointURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{"origin only", "http://alloy:4318", "http://alloy:4318/v1/traces"},
		{"trailing slash", "http://alloy:4318/", "http://alloy:4318/v1/traces"},
		{"https origin", "https://collector.example.com", "https://collector.example.com/v1/traces"},
		{"explicit path preserved", "http://alloy:4318/v1/traces", "http://alloy:4318/v1/traces"},
		{"custom path preserved", "http://gw.example.com/otlp/v1/traces", "http://gw.example.com/otlp/v1/traces"},
		{"unparseable returned as-is", "://nope", "://nope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tracesEndpointURL(tt.endpoint); got != tt.want {
				t.Errorf("tracesEndpointURL(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

// TestSetup_ExportsToTracesPath pins the behaviour that actually broke in
// production: with an origin-only endpoint the exporter POSTed to "/", the
// collector answered 404, and every span was discarded. The failure is
// invisible from inside the process — a rejected export is reported through the
// OTEL error handler, not through mcpgate_otel_spans_dropped_total — so only an
// end-to-end assertion on the request path catches a regression here.
func TestSetup_ExportsToTracesPath(t *testing.T) {
	paths := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case paths <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := context.Background()
	provider, err := Setup(ctx, Config{
		Endpoint:    srv.URL, // origin only — no path, as operators configure it
		ServiceName: "test",
		SampleRate:  1.0,
		Version:     "test",
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	_, span := provider.tp.Tracer("test").Start(ctx, "test-span")
	span.End()

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := provider.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case got := <-paths:
		if got != defaultTracesPath {
			t.Errorf("exporter POSTed to %q, want %q", got, defaultTracesPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collector received no export")
	}
}

func TestSetup_InvalidEndpoint(t *testing.T) {
	// Setup with an endpoint that can't be reached — the exporter creation
	// itself doesn't fail (it's lazy), so we just verify it returns without error.
	provider, err := Setup(context.Background(), Config{
		Endpoint:    "http://localhost:0",
		ServiceName: "test",
		SampleRate:  0.5,
		Version:     "test",
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if provider.tp == nil {
		t.Error("expected non-nil TracerProvider for non-empty endpoint")
	}

	// Shutdown should work
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}
