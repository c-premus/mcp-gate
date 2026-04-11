package metrics

import (
	"log/slog"
	"net"
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
// trustedProxies controls which peers are trusted for X-Forwarded-For /
// X-Real-IP header extraction. Pass nil to always use RemoteAddr.
func Middleware(next http.Handler, trustedProxies []*net.IPNet) http.Handler {
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

		HTTPRequestsTotal.WithLabelValues(r.Method, route, status).Inc()
		HTTPRequestDuration.WithLabelValues(r.Method, route, status).Observe(duration)

		slog.Info("request",
			"method", r.Method,
			"path", truncate(r.URL.Path, maxLoggedFieldBytes),
			"status", rec.statusCode,
			"duration_ms", int(duration*1000),
			"client_ip", realip.Extract(r, trustedProxies),
			"user_agent", truncate(r.Header.Get("User-Agent"), maxLoggedFieldBytes),
		)
	})
}
