package metrics

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/c-premus/mcp-gate/internal/metadata"
	"github.com/c-premus/mcp-gate/internal/realip"
)

// maxLoggedFieldBytes bounds logged request-derived strings to prevent
// attacker-controlled log amplification via oversized paths or User-Agent
// headers. 512 B is well above typical values while still capping worst-case
// log line size.
const maxLoggedFieldBytes = 512

// truncate returns s unchanged if within maxBytes, otherwise truncates at a
// safe UTF-8 boundary and appends a marker. The cap is a byte cap, not a rune
// cap, to make worst-case log line size predictable.
func truncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Back off to the last valid UTF-8 start byte so we never emit a
	// truncated multi-byte sequence.
	cut := maxBytes
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…(truncated)"
}

// RouteClassifier maps a request path to a bounded route label for metrics.
//
// This runs OUTSIDE the mux, so it must independently reproduce the mux's
// routing decision or the route label lies about where a request went.
func RouteClassifier(r *http.Request) string {
	path := r.URL.Path
	switch {
	case path == metadata.WellKnownPath:
		return "metadata"
	// The mux serves the RFC 9728 §3.1 path-inserted form and answers 404 for
	// the rest of the subtree; both are metadata traffic, not proxy traffic.
	//
	// The trailing "/" is load-bearing: a bare prefix match would also claim
	// "/.well-known/oauth-protected-resourceXYZ", which the mux routes to the
	// proxy, and the label would then contradict where the request went.
	case strings.HasPrefix(path, metadata.WellKnownPath+"/"):
		return "metadata"
	case path == "/healthz":
		return "healthz"
	default:
		return "proxy"
	}
}

// methodLabel maps an HTTP method to a bounded Prometheus label. Arbitrary
// strings from a method-scanning client would otherwise create unbounded
// series on mcpgate_http_requests_total.
func methodLabel(m string) string {
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodHead, http.MethodOptions:
		return m
	default:
		return "OTHER"
	}
}

// responseRecorder wraps http.ResponseWriter to capture the status code.
// It implements http.Flusher (required for SSE streaming) and Unwrap()
// (required for Go's ResponseController).
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if !r.written {
		r.statusCode = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.statusCode = http.StatusOK
		r.written = true
	}
	return r.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for SSE streaming support.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter for Go's ResponseController.
func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Middleware records HTTP request count and duration metrics.
// It reads the client IP from the request context (set by realip.Middleware).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		route := RouteClassifier(r)

		rec := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rec, r)

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(rec.statusCode)
		method := methodLabel(r.Method)

		HTTPRequestsTotal.WithLabelValues(method, route, status).Inc()
		HTTPRequestDuration.WithLabelValues(method, route, status).Observe(duration)

		// MCP request-metadata headers are only meaningful on proxied traffic;
		// /healthz and the metadata endpoint never carry them. Recording only
		// on the proxy route keeps "absent" meaning "an MCP client that didn't
		// send it" rather than being swamped by health probes.
		//
		// Read-only: see the rule in mcp.go. These values are observed, never
		// acted on.
		mcpMethod, mcpName := "", ""
		if route == "proxy" {
			mcpMethod = r.Header.Get(HeaderMCPMethod)
			mcpName = r.Header.Get(HeaderMCPName)
			MCPRequestsTotal.WithLabelValues(
				mcpMethodLabel(mcpMethod),
				mcpProtocolVersionLabel(r.Header.Get(HeaderMCPProtocolVersion)),
			).Inc()
		}

		// Successful healthz probes fire every 30s from Docker + Traefik +
		// Prometheus target checks; at info level that's ~thousands of lines
		// per day of pure noise in Loki. Drop them to debug so operators only
		// see healthz when something is actually wrong (non-2xx status).
		logFn := slog.Info
		if route == "healthz" && rec.statusCode == http.StatusOK {
			logFn = slog.Debug
		}
		args := []any{
			"method", r.Method,
			"path", truncate(r.URL.Path, maxLoggedFieldBytes),
			"status", rec.statusCode,
			"duration_ms", int(duration*1000),
			"client_ip", realip.FromContext(r),
			"user_agent", truncate(r.Header.Get("User-Agent"), maxLoggedFieldBytes),
		}
		// Only attach MCP fields when the client actually sent them, so log
		// lines from non-MCP traffic don't carry empty keys.
		if mcpMethod != "" {
			args = append(args, "mcp_method", truncate(mcpMethod, maxLoggedFieldBytes))
		}
		if mcpName != "" {
			// Logged raw and truncated — never Base64-decoded. See
			// isBase64Sentinel for why. Unlike the metric label, mcp_name is
			// unbounded (for resources/read it carries params.uri), which is
			// exactly why it is a log field and not a label.
			args = append(args,
				"mcp_name", truncate(mcpName, maxLoggedFieldBytes),
				"mcp_name_encoded", isBase64Sentinel(mcpName),
			)
		}
		logFn("request", args...)
	})
}
