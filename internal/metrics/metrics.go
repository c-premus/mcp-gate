// Package metrics provides Prometheus metric definitions and a metrics server.
//
// All metrics use the "mcpgate_" prefix and cover HTTP requests, authentication
// outcomes, proxy latency, JWKS key counts, rate limiting, and connection
// tracking. The package also provides HTTP middleware for request logging
// and metric recording.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metric definitions.
var (
	Info = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mcpgate_info",
		Help: "Build information (set to 1).",
	}, []string{"version"})

	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpgate_http_requests_total",
		Help: "Total HTTP requests received.",
	}, []string{"method", "route", "status_code"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mcpgate_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status_code"})

	AuthValidationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpgate_auth_validations_total",
		Help: "JWT validation outcomes.",
	}, []string{"outcome"})

	ProxyRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpgate_proxy_requests_total",
		Help: "Upstream proxy response codes.",
	}, []string{"status_code"})

	ProxyRequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mcpgate_proxy_request_duration_seconds",
		Help:    "Upstream proxy latency in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	JWKSKeysLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mcpgate_jwks_keys_loaded",
		Help: "Number of cached JWKS keys. Updated on each poll of the JWKS storage.",
	})

	// JWKSRefreshErrorsTotal is incremented by the jwkset RefreshErrorHandler.
	// Primary alerting signal for JWKS refresh failures — alert on a non-zero
	// increase over a window longer than the refresh interval.
	JWKSRefreshErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcpgate_jwks_refresh_errors_total",
		Help: "Total JWKS refresh failures reported by the refresh goroutine.",
	})

	// JWKSPollErrorsTotal counts errors observed by the local polling goroutine
	// when reading the JWKS storage. Distinct from JWKSRefreshErrorsTotal which
	// surfaces upstream-fetch failures via jwkset's RefreshErrorHandler — this
	// counter catches local read failures (storage layer bugs, ctx cancellation
	// races) that would otherwise leave the keys-loaded gauge silently stale.
	JWKSPollErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcpgate_jwks_poll_errors_total",
		Help: "Number of JWKS poll-loop read errors (correctness signal — distinct from refresh errors which come from the upstream JWKS endpoint).",
	})

	// JWKSLastKeyChangeTimestamp records the Unix seconds time at which the
	// polling goroutine last observed a change in the cached key set (set
	// membership, not just count). jwkset does not expose a refresh-success
	// callback, so this is inferred by comparing polled key IDs.
	//
	// Note: this does NOT measure every successful refresh — a refresh that
	// returns the identical key set will not bump this timestamp. It is a
	// correctness signal, not a liveness signal. Use mcpgate_jwks_refresh_errors_total
	// for liveness alerting.
	JWKSLastKeyChangeTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mcpgate_jwks_last_key_change_timestamp_seconds",
		Help: "Unix seconds of the last observed change in the JWKS key set.",
	})

	RateLimitedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcpgate_rate_limited_total",
		Help: "Total requests rejected by rate limiting.",
	})

	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mcpgate_active_connections",
		Help: "Number of active TCP connections.",
	})

	ActiveRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mcpgate_active_requests",
		Help: "Number of active HTTP requests being processed.",
	})

	ConcurrentLimitedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcpgate_concurrent_limited_total",
		Help: "Total requests rejected by concurrent request limiting.",
	})

	// TrustedProxyCIDRs is the count of TRUSTED_PROXIES CIDRs parsed at startup.
	// Operator-facing config-audit signal: when a deployment behind Cloudflare
	// or another fronting proxy has TRUSTED_PROXIES misconfigured, every client
	// IP collapses to the upstream proxy's IP and per-IP rate limiting is
	// silently defeated. This gauge makes the configured count visible on the
	// dashboard so a value of 0 (or unexpectedly low) is immediately obvious.
	// No per-CIDR label — fixed cardinality keeps the series cheap regardless
	// of list length.
	TrustedProxyCIDRs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "mcpgate_trusted_proxy_cidrs",
		Help: "Number of trusted proxy CIDRs parsed from TRUSTED_PROXIES at startup.",
	})

	// OTELSpansDroppedTotal is a placeholder counter for spans dropped by the
	// OTLP batch span processor when its queue is full. The OTel Go SDK
	// (sdk/trace v1.43.0) tracks dropped spans internally via an unexported
	// atomic counter on batchSpanProcessor — there is no public callback,
	// accessor, or option to observe this count. Until the SDK exposes a hook
	// (see https://github.com/open-telemetry/opentelemetry-go/issues — audit
	// note in resilience M5), this counter remains permanently zero. The
	// metric is registered anyway so the dashboard panel can render
	// consistently and so wiring is in place for the day a hook lands.
	OTELSpansDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcpgate_otel_spans_dropped_total",
		Help: "Total OTLP spans dropped by the batch span processor due to queue-full or export failure. Currently always zero: the OTel Go SDK does not expose a public hook for queue-full events. Placeholder kept for dashboard rendering.",
	})

	// proxy stream observability ------------------------------------------------
	// SSE / streamable-http response path: byte-size distribution and disconnect
	// causes (client cancellation, server-side idle timeout). Grouped here so
	// future stream-related metrics stay co-located.

	// ProxySSEDisconnectsTotal counts SSE responses that ended before the
	// upstream completed the stream. reason="client_cancel" — request context
	// cancelled during streaming. reason="idle_timeout" — SSE_IDLE_TIMEOUT
	// fired with no bytes flowing.
	ProxySSEDisconnectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcpgate_sse_disconnects_total",
		Help: "Total SSE responses terminated before normal completion, labelled by reason.",
	}, []string{"reason"})

	// ProxyResponseBytes observes the byte size of upstream responses streamed
	// to the client. Buckets span 1KiB to 64MiB to cover both small JSON tool
	// responses and long SSE streams.
	ProxyResponseBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "mcpgate_proxy_response_bytes",
		Help:    "Upstream response body size in bytes (observed at body close).",
		Buckets: []float64{1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864},
	})
)

// Server serves Prometheus metrics and a health check on a separate port.
type Server struct {
	server *http.Server
	ln     net.Listener
}

// NewServer creates a metrics server bound to the given address.
// It serves /metrics (promhttp) and /healthz on the metrics port.
func NewServer(addr string) (*Server, error) {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}

	return &Server{
		server: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		ln: ln,
	}, nil
}

// Addr returns the actual bound address.
func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

// Serve starts serving metrics. It blocks until the server is shut down.
func (s *Server) Serve() error {
	slog.Info("metrics server starting", "addr", s.Addr())
	if err := s.server.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully shuts down the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
