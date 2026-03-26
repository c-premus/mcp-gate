// Package proxy provides the reverse proxy to upstream MCP servers.
//
// It strips the client Authorization header before forwarding (the upstream
// authenticates separately), removes hop-by-hop headers, and supports SSE
// streaming via FlushInterval for MCP streamable-http transport.
package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/c-premus/mcp-gate/internal/metrics"
)

// TransportConfig holds timeout and connection pool settings for the upstream transport.
type TransportConfig struct {
	DialTimeout           time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	IdleConnTimeout       time.Duration
	KeepAlive             time.Duration
}

// DefaultTransportConfig returns production defaults for the upstream transport.
// ResponseHeaderTimeout (120s) times the wait for the first response header byte
// from upstream. MCP tool calls (e.g., complex PromQL queries) may need the full
// duration. Override via UPSTREAM_TIMEOUT env var.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		DialTimeout:           5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		KeepAlive:             30 * time.Second,
	}
}

type contextKey struct{}

// New creates a reverse proxy targeting the given upstream URL.
// It uses the Rewrite API (not Director) for safer hop-by-hop handling,
// strips sensitive headers, and supports SSE streaming via FlushInterval: -1.
func New(upstreamURL *url.URL, tc TransportConfig) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   tc.DialTimeout,
				KeepAlive: tc.KeepAlive,
			}).DialContext,
			TLSHandshakeTimeout:   tc.TLSHandshakeTimeout,
			ResponseHeaderTimeout: tc.ResponseHeaderTimeout,
			MaxIdleConns:          tc.MaxIdleConns,
			MaxIdleConnsPerHost:   tc.MaxIdleConnsPerHost,
			IdleConnTimeout:       tc.IdleConnTimeout,
			ForceAttemptHTTP2:     true,
		},
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstreamURL)
			r.SetXForwarded()
			r.Out.Header.Del("Authorization") // User JWT must not reach upstream
			r.Out.Header.Del("Cookie")        // Prevent session/CSRF token leakage

			// Strip access_token from query params to prevent log leakage
			q := r.Out.URL.Query()
			q.Del("access_token")
			r.Out.URL.RawQuery = q.Encode()

			// Store start time for duration tracking
			r.Out = r.Out.WithContext(context.WithValue(r.Out.Context(), contextKey{}, time.Now()))
		},
		FlushInterval: -1, // Flush immediately for SSE/streamable-http
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("upstream proxy error",
				"method", r.Method,
				"path", r.URL.Path,
				"error", err,
			)

			if start, ok := r.Context().Value(contextKey{}).(time.Time); ok {
				metrics.ProxyRequestDuration.Observe(time.Since(start).Seconds())
			}
			metrics.ProxyRequestsTotal.WithLabelValues("502").Inc()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "upstream_error",
				"error_description": "The upstream service is unavailable",
			})
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Server")
			resp.Header.Del("X-Powered-By")

			if start, ok := resp.Request.Context().Value(contextKey{}).(time.Time); ok {
				metrics.ProxyRequestDuration.Observe(time.Since(start).Seconds())
			}
			metrics.ProxyRequestsTotal.WithLabelValues(strconv.Itoa(resp.StatusCode)).Inc()

			return nil
		},
	}
}
