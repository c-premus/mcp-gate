// Package otel provides OpenTelemetry tracing setup with OTLP HTTP export.
//
// Tracing is optional: if no OTLP endpoint is configured, Setup returns nil.
// TLS is auto-detected from the endpoint URL scheme — https endpoints use
// TLS by default, http endpoints use WithInsecure.
package otel

import (
	"context"
	"fmt"
	"net/url"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// defaultTracesPath is the OTLP/HTTP request path for the traces signal.
const defaultTracesPath = "/v1/traces"

// tracesEndpointURL fills in the OTLP traces path when the operator supplied
// only an origin.
//
// mcp-gate's knob is OTEL_EXPORTER_OTLP_ENDPOINT — the *generic* endpoint
// variable, which the OTLP specification says the per-signal path is appended
// to (unlike OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, which is used verbatim).
// otlptracehttp.WithEndpointURL takes the URL's path verbatim either way and
// applies no such default, so the documented "http://collector:4318" form
// exported to "/" and every batch came back 404 — silently, because a failed
// export is reported through the OTEL error handler and never touches the
// mcpgate_otel_spans_dropped_total counter (see the note in Setup).
//
// An endpoint that already carries a path is left alone, so an operator can
// still point at a collector mounted somewhere non-standard.
func tracesEndpointURL(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Path != "" && u.Path != "/") {
		return endpoint
	}
	u.Path = defaultTracesPath
	return u.String()
}

// Config holds OTEL tracing configuration.
type Config struct {
	Endpoint    string  // OTLP HTTP endpoint (e.g. "http://alloy:4318"). Empty = disabled.
	ServiceName string  // Service name in traces.
	SampleRate  float64 // Sampling rate (0.0-1.0).
	Version     string  // Service version.
}

// Provider wraps the TracerProvider for lifecycle management.
type Provider struct {
	tp *sdktrace.TracerProvider
}

// Setup creates and configures an OTEL TracerProvider. If cfg.Endpoint is empty,
// it returns a no-op provider (Shutdown is safe to call).
func Setup(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Endpoint == "" {
		return &Provider{}, nil
	}

	endpoint := tracesEndpointURL(cfg.Endpoint)

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(endpoint),
	}
	// Parse the endpoint and compare the normalized scheme. strings.HasPrefix
	// on "http://" would miss "HTTP://" and fall through to TLS — which then
	// fails to negotiate against a plain-HTTP collector with an opaque error.
	// url.Parse lowercases the scheme so the comparison is stable.
	if u, err := url.Parse(endpoint); err == nil && u.Scheme == "http" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otel exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.Version),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))

	// Span-drop observability (resilience M5, mcpgate_otel_spans_dropped_total):
	// the SDK's batch span processor (sdk/trace v1.43.0) increments an
	// unexported atomic counter when its queue is full, but exposes no public
	// callback or accessor — there is no WithDropHandler-style option as of
	// today. Until upstream lands a hook, the counter declared in
	// internal/metrics is a documented always-zero placeholder. Revisit when
	// open-telemetry/opentelemetry-go ships a public observation surface.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{tp: tp}, nil
}

// Shutdown flushes and shuts down the TracerProvider. Safe to call on a no-op provider.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.tp == nil {
		return nil
	}
	return p.tp.Shutdown(ctx)
}
