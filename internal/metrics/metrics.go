// Package metrics provides Prometheus metric definitions and a metrics server.
//
// All metrics use the "mcpgate_" prefix and cover HTTP requests, authentication
// outcomes, proxy latency, JWKS key counts, rate limiting, and connection
// tracking. The package also provides HTTP middleware for request logging
// and metric recording.
package metrics

import (
	"context"
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
	if err := s.server.Serve(s.ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully shuts down the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
