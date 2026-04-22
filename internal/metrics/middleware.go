package metrics

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

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
func RouteClassifier(r *http.Request) string {
	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource":
		return "metadata"
	case "/healthz":
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

		// Successful healthz probes fire every 30s from Docker + Traefik +
		// Prometheus target checks; at info level that's ~thousands of lines
		// per day of pure noise in Loki. Drop them to debug so operators only
		// see healthz when something is actually wrong (non-2xx status).
		logFn := slog.Info
		if route == "healthz" && rec.statusCode == http.StatusOK {
			logFn = slog.Debug
		}
		logFn("request",
			"method", r.Method,
			"path", truncate(r.URL.Path, maxLoggedFieldBytes),
			"status", rec.statusCode,
			"duration_ms", int(duration*1000),
			"client_ip", realip.FromContext(r),
			"user_agent", truncate(r.Header.Get("User-Agent"), maxLoggedFieldBytes),
		)
	})
}
