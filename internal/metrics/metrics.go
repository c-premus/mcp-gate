// Package metrics provides Prometheus metric definitions and a metrics server.
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
		Help: "Number of cached JWKS keys.",
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
