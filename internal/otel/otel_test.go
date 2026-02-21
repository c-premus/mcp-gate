package otel

import (
	"context"
	"testing"
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
