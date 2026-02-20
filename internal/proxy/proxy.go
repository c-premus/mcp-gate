// Package proxy provides the reverse proxy to upstream MCP servers.
package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// New creates a reverse proxy targeting the given upstream URL.
// It uses the Rewrite API (not Director) for safer hop-by-hop handling,
// strips sensitive headers, and supports SSE streaming via FlushInterval: -1.
func New(upstreamURL *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstreamURL)
			r.SetXForwarded()
			r.Out.Header.Del("Authorization") // User JWT must not reach upstream
			r.Out.Header.Del("Cookie")        // Prevent session/CSRF token leakage

			// Strip access_token from query params to prevent log leakage
			q := r.Out.URL.Query()
			q.Del("access_token")
			r.Out.URL.RawQuery = q.Encode()
		},
		FlushInterval: -1, // Flush immediately for SSE/streamable-http
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("upstream proxy error",
				"method", r.Method,
				"path", r.URL.Path,
				"error", err,
			)
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
			return nil
		},
	}
}
