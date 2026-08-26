// Package proxy provides the reverse proxy to upstream MCP servers.
//
// It strips the client Authorization header before forwarding (the upstream
// authenticates separately), removes hop-by-hop headers, and supports SSE
// streaming via FlushInterval for MCP streamable-http transport.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/c-premus/mcp-gate/internal/metrics"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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
	// SSEIdleTimeout bounds idle time between bytes on a streamed
	// text/event-stream response. ResponseHeaderTimeout only covers the wait
	// for the first byte; without an idle bound, a silent SSE stream pins a
	// goroutine, a TCP slot, and a concurrent-limit slot indefinitely. Zero
	// disables the idle bound.
	SSEIdleTimeout time.Duration
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
		SSEIdleTimeout:        5 * time.Minute,
	}
}

type contextKey struct{}

// countingBody wraps an upstream response body so we can observe the number of
// bytes streamed to the client. ProxyResponseBytes is observed exactly once on
// Close (which httputil.ReverseProxy always calls), so a buffered SSE that the
// client cancels mid-stream still emits a histogram sample.
type countingBody struct {
	io.ReadCloser
	bytes  atomic.Int64
	closed atomic.Bool
	onDone func(bytesRead int64)
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.bytes.Add(int64(n))
	}
	return n, err
}

func (c *countingBody) Close() error {
	err := c.ReadCloser.Close()
	if c.closed.CompareAndSwap(false, true) && c.onDone != nil {
		c.onDone(c.bytes.Load())
	}
	return err
}

// idleTimeoutBody resets a timer on each successful Read; on timer fire, the
// underlying body is closed which surfaces as an io.ErrUnexpectedEOF / closed
// network connection error to the proxy's copy loop, terminating the stream.
type idleTimeoutBody struct {
	io.ReadCloser
	timeout time.Duration

	mu     sync.Mutex
	timer  *time.Timer
	fired  atomic.Bool
	closed atomic.Bool
}

func newIdleTimeoutBody(rc io.ReadCloser, timeout time.Duration) *idleTimeoutBody {
	b := &idleTimeoutBody{ReadCloser: rc, timeout: timeout}
	b.mu.Lock()
	b.timer = time.AfterFunc(timeout, b.onIdle)
	b.mu.Unlock()
	return b
}

func (b *idleTimeoutBody) onIdle() {
	if b.closed.Load() {
		return
	}
	b.fired.Store(true)
	_ = b.ReadCloser.Close()
}

func (b *idleTimeoutBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.mu.Lock()
		if b.timer != nil && !b.closed.Load() {
			b.timer.Reset(b.timeout)
		}
		b.mu.Unlock()
	}
	return n, err
}

func (b *idleTimeoutBody) Close() error {
	b.closed.Store(true)
	b.mu.Lock()
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.mu.Unlock()
	return b.ReadCloser.Close()
}

// idleFired reports whether the idle timer fired (rather than the client or
// upstream ending the stream normally). Safe to call after Close.
func (b *idleTimeoutBody) idleFired() bool { return b.fired.Load() }

// New creates a reverse proxy targeting the given upstream URL.
// It uses the Rewrite API (not Director) for safer hop-by-hop handling,
// strips sensitive headers, and supports SSE streaming via FlushInterval: -1.
func New(upstreamURL *url.URL, tc TransportConfig) *httputil.ReverseProxy {
	baseTransport := &http.Transport{
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
	}

	return &httputil.ReverseProxy{
		Transport: otelhttp.NewTransport(baseTransport),
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstreamURL)
			// SetXForwarded uses r.In.RemoteAddr / r.In.Host / r.In.TLS to set
			// X-Forwarded-{For,Host,Proto} on the outbound request. Go's
			// stdlib (reverseproxy.go) already strips any CLIENT-supplied
			// Forwarded / X-Forwarded-* headers from r.Out before Rewrite
			// runs, so SetXForwarded cannot reflect client-controlled values
			// — the outbound headers always reflect the direct peer (the
			// fronting proxy, where one is deployed). No trusted-proxy
			// gating needed here; realip
			// handles the XFF walk separately for rate-limit keying and logs.
			r.SetXForwarded()
			r.Out.Header.Del("Authorization") // User JWT must not reach upstream
			r.Out.Header.Del("Cookie")        // Prevent session/CSRF token leakage

			// Belt-and-suspenders: also strip from r.In so the ErrorHandler —
			// which receives the inbound request — cannot accidentally log the
			// user's bearer token if a future maintainer adds the header map
			// to the structured log line.
			r.In.Header.Del("Authorization")
			r.In.Header.Del("Cookie")

			// Strip access_token from query params to prevent log leakage.
			// RFC 6750 §2.3 deprecates the URI query method and MCP
			// 2026-07-28 disallows it; stripping alone is silent, so signal
			// receipt too — the request still succeeds, and the counter plus
			// Warn line are the only way an operator learns a connector is
			// putting bearer tokens in URLs.
			//
			// Guarding on Has() also keeps this off the hot path: Rewrite runs
			// on every proxied request, and re-encoding RawQuery when there is
			// nothing to remove is pure waste (see
			// docs/audit/2026-04-22-go-idioms.md:203).
			//
			// Log method and path only — never RawQuery, never the parameter
			// value. Echoing the token into the log line is the exact leak
			// this signal exists to report.
			if q := r.Out.URL.Query(); q.Has("access_token") {
				slog.Warn("deprecated access_token query parameter",
					"method", r.In.Method,
					"path", r.In.URL.Path,
				)
				metrics.DeprecatedAccessTokenQueryTotal.Inc()
				q.Del("access_token")
				r.Out.URL.RawQuery = q.Encode()
			}

			// Store start time for duration tracking on r.Out.
			// httputil.ReverseProxy passes pr.Out (as outreq) to both ErrorHandler
			// and ModifyResponse, so a single stash covers both paths.
			r.Out = r.Out.WithContext(context.WithValue(r.Out.Context(), contextKey{}, time.Now()))
		},
		FlushInterval: -1, // Flush immediately for SSE/streamable-http
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if start, ok := r.Context().Value(contextKey{}).(time.Time); ok {
				metrics.ProxyRequestDuration.Observe(time.Since(start).Seconds())
			}

			// An over-limit request body reaches us as a read error, because
			// http.MaxBytesReader is installed by the caller but only the
			// ReverseProxy actually reads the body. Reporting that as
			// "upstream unavailable" is wrong twice over: it blames a healthy
			// upstream for the client's request, and it inflates the 5xx ratio
			// the deploy alert watches. MCP 2026-07-28 also asks intermediaries
			// to "return an appropriate HTTP error status for validation
			// failures".
			// errors.As, not errors.AsType: the module's language floor is
			// Go 1.26 so CodeQL's Go extractor can analyze it (see go.mod).
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				slog.Warn("request body exceeds limit",
					"method", r.Method,
					"path", r.URL.Path,
					"limit_bytes", maxBytesErr.Limit,
				)
				metrics.ProxyRequestsTotal.WithLabelValues("413").Inc()

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":             "payload_too_large",
					"error_description": "The request body exceeds the maximum allowed size",
				})
				return
			}

			// Log a classified category rather than err.Error(): the raw
			// transport error embeds internal topology (upstream IP and port
			// for dial failures, the full outbound URL for *url.Error), which
			// would then land in Loki. The category plus the 502 counter is
			// enough to diagnose; the raw error is kept at Debug for local
			// troubleshooting.
			category := classifyProxyError(err)
			slog.Error("upstream proxy error",
				"method", r.Method,
				"path", r.URL.Path,
				"category", category,
			)
			slog.Debug("upstream proxy error (detail)", "category", category, "error", err)
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

			isSSE := strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
			reqCtx := resp.Request.Context()

			// MCP 2026-07-28 Streamable HTTP: "When initiating an SSE stream,
			// servers SHOULD include the X-Accel-Buffering: no header in the
			// HTTP response. This instructs reverse proxies to disable response
			// buffering."
			//
			// mcp-gate does not buffer (FlushInterval: -1), but it is not the
			// last proxy in the chain — any edge proxy or CDN between here and
			// the client buffers by default, and this header is the conventional
			// signal to them. Setting it (rather than only forwarding upstream's) means
			// the guarantee holds even when the upstream MCP server predates
			// this requirement.
			if isSSE {
				resp.Header.Set("X-Accel-Buffering", "no")
			}

			// SSE idle timeout: wrap the body so a silent stream is force-closed
			// after the configured idle period. We layer this UNDER the byte
			// counter so byte counts include partial reads before idle close.
			var idle *idleTimeoutBody
			if isSSE && tc.SSEIdleTimeout > 0 {
				idle = newIdleTimeoutBody(resp.Body, tc.SSEIdleTimeout)
				resp.Body = idle
			}

			counted := &countingBody{
				ReadCloser: resp.Body,
				onDone: func(bytesRead int64) {
					metrics.ProxyResponseBytes.Observe(float64(bytesRead))
					if !isSSE {
						return
					}
					switch {
					case idle != nil && idle.idleFired():
						metrics.ProxySSEDisconnectsTotal.WithLabelValues("idle_timeout").Inc()
						slog.Warn("SSE stream closed by idle timeout",
							"path", resp.Request.URL.Path,
							"timeout", tc.SSEIdleTimeout,
							"bytes", bytesRead,
						)
					case errors.Is(reqCtx.Err(), context.Canceled),
						errors.Is(reqCtx.Err(), context.DeadlineExceeded):
						metrics.ProxySSEDisconnectsTotal.WithLabelValues("client_cancel").Inc()
					}
				},
			}
			resp.Body = counted

			return nil
		},
	}
}

// classifyProxyError maps a reverse-proxy transport error to a fixed-cardinality
// category string safe to log at Error level. The raw error embeds internal
// topology — `dial tcp 10.0.0.7:8000: connect: connection refused` names the
// upstream address, and *url.Error carries the full outbound URL — which must
// not reach Loki. The default arm bounds cardinality.
//
// Order matters: *net.DNSError and the syscall errnos are checked BEFORE the
// generic net.Error.Timeout() arm, because a DNS lookup that timed out is both
// a *net.DNSError and a net.Error reporting Timeout() == true; classifying it
// as "timeout" would hide a resolver outage behind a generic slow-upstream
// category.
//
// This runs on the upstream-failure path, i.e. exactly when the proxy is
// already degraded, so it never dereferences anything: a panic here would turn
// a 502 into a crash. errors.As on a nil target pointer is safe.
func classifyProxyError(err error) string {
	var dnsErr *net.DNSError
	var netErr net.Error

	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &dnsErr):
		return "dns_failure"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	case errors.Is(err, net.ErrClosed):
		return "connection_closed"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	default:
		return "other"
	}
}
