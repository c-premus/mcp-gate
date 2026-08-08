package proxy_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/c-premus/mcp-gate/internal/proxy"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// histogramSampleCount reads the current sample count from a Prometheus histogram.
// Used to verify duration observations fire on specific code paths.
func histogramSampleCount(t *testing.T, h interface {
	Write(*dto.Metric) error
},
) uint64 {
	t.Helper()
	m := &dto.Metric{}
	if err := h.Write(m); err != nil {
		t.Fatalf("histogram Write: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

// echoUpstream returns headers and URL received by the upstream, as JSON.
func echoUpstream() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"authorization":     r.Header.Get("Authorization"),
			"cookie":            r.Header.Get("Cookie"),
			"x-forwarded-for":   r.Header.Get("X-Forwarded-For"),
			"x-forwarded-proto": r.Header.Get("X-Forwarded-Proto"),
			"url":               r.URL.String(),
		}
		w.Header().Set("Server", "mcp-grafana/1.0")
		w.Header().Set("X-Powered-By", "Go")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return u
}

func doProxyRequest(t *testing.T, upstream *httptest.Server, req *http.Request) *http.Response {
	t.Helper()
	p := proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig())
	rec := httptest.NewServer(p)
	defer rec.Close()

	req.URL, _ = url.Parse(rec.URL + req.URL.String())
	req.RequestURI = ""
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	return resp
}

type echoResponse struct {
	Authorization   string `json:"authorization"`
	Cookie          string `json:"cookie"`
	XForwardedFor   string `json:"x-forwarded-for"`
	XForwardedProto string `json:"x-forwarded-proto"`
	URL             string `json:"url"`
}

// doProxyEcho sends a request through the proxy and decodes the upstream echo response.
func doProxyEcho(t *testing.T, upstream *httptest.Server, req *http.Request) echoResponse {
	t.Helper()
	resp := doProxyRequest(t, upstream, req)
	defer func() { _ = resp.Body.Close() }()
	var echo echoResponse
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo: %v", err)
	}
	return echo
}

func TestAuthorizationHeaderStripped(t *testing.T) {
	upstream := echoUpstream()
	defer upstream.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer secret-token")

	echo := doProxyEcho(t, upstream, req)

	if echo.Authorization != "" {
		t.Errorf("Authorization header not stripped: got %q", echo.Authorization)
	}
}

func TestCookieHeaderStripped(t *testing.T) {
	upstream := echoUpstream()
	defer upstream.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Cookie", "session=abc123")

	echo := doProxyEcho(t, upstream, req)

	if echo.Cookie != "" {
		t.Errorf("Cookie header not stripped: got %q", echo.Cookie)
	}
}

func TestAccessTokenQueryParamStripped(t *testing.T) {
	upstream := echoUpstream()
	defer upstream.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/test?access_token=secret&foo=bar", http.NoBody)

	echo := doProxyEcho(t, upstream, req)

	if strings.Contains(echo.URL, "access_token") {
		t.Errorf("access_token not stripped from URL: got %q", echo.URL)
	}
	if !strings.Contains(echo.URL, "foo=bar") {
		t.Errorf("other params should be preserved: got %q", echo.URL)
	}
}

func TestXForwardedForSet(t *testing.T) {
	upstream := echoUpstream()
	defer upstream.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)

	echo := doProxyEcho(t, upstream, req)

	if echo.XForwardedFor == "" {
		t.Error("X-Forwarded-For not set")
	}
}

func TestErrorHandlerReturns502(t *testing.T) {
	// Upstream that immediately closes the connection
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support Hijack")
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer upstream.Close()

	p := proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if body["error"] != "upstream_error" {
		t.Errorf("error = %q, want upstream_error", body["error"])
	}
}

// TestErrorHandlerObservesDuration verifies that ProxyRequestDuration is observed
// on the 502 error path. The Rewrite callback stashes the start time on both r.In
// and r.Out because httputil.ReverseProxy passes pr.In (not pr.Out) to ErrorHandler;
// a regression that drops the r.In stash would silently stop observing error-path
// latencies while ProxyRequestsTotal continues to increment.
func TestErrorHandlerObservesDuration(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		// Handler never runs — Hijack and close to trigger ErrorHandler in the proxy.
	}))
	// Close immediately so dial fails.
	upstream.Close()

	before := histogramSampleCount(t, metrics.ProxyRequestDuration)

	p := proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}

	after := histogramSampleCount(t, metrics.ProxyRequestDuration)
	if after != before+1 {
		t.Fatalf("ProxyRequestDuration sample count = %d, want %d (error path did not observe duration)", after, before+1)
	}
}

func TestErrorHandlerNoInternalHostnames(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support Hijack")
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer upstream.Close()

	// The log surface matters as much as the response body: the raw transport
	// error names the upstream host:port, and that line ships to Loki.
	// JSON handler with nil options defaults to Info level, so the Debug
	// "detail" line carrying the raw error is deliberately not captured.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p := proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "127.0.0.1") || strings.Contains(body, "localhost") {
		t.Errorf("error body leaks internal hostnames: %s", body)
	}

	logged := buf.String()
	for _, unwanted := range []string{"127.0.0.1", "localhost"} {
		if strings.Contains(logged, unwanted) {
			t.Errorf("log leaks internal hostname %q\n  got: %s", unwanted, logged)
		}
	}
}

// TestErrorHandlerLogsNoUpstreamAddress pins the F15 log-surface fix: the
// Error-level line carries a bounded "category" field instead of the raw
// transport error, so upstream IPs, ports, and dial syntax never reach Loki.
//
// The exact category is deliberately NOT asserted here. A 1ns dial produces a
// platform- and Go-version-dependent error shape (i/o timeout vs. connection
// refused vs. a bare context deadline), so pinning the value would make this
// test flaky. Exact values are covered by TestClassifyProxyError with
// synthetic errors.
//
// slog.NewJSONHandler(&buf, nil) defaults to Info level, so the slog.Debug
// "upstream proxy error (detail)" line — the only place the raw error still
// appears — is not captured. That absence is itself the assertion: the raw
// error is Debug-only, reachable via LOG_LEVEL=debug.
func TestErrorHandlerLogsNoUpstreamAddress(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	tc := proxy.DefaultTransportConfig()
	tc.DialTimeout = time.Nanosecond // Force ErrorHandler

	// RFC 5737 TEST-NET-1 — guaranteed non-routable.
	p := proxy.New(mustParseURL(t, "http://192.0.2.1:1"), tc)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}

	logged := buf.String()
	for _, want := range []string{"upstream proxy error", "category"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log missing %q\n  got: %s", want, logged)
		}
	}
	for _, unwanted := range []string{"192.0.2.1", "dial tcp", "connect:"} {
		if strings.Contains(logged, unwanted) {
			t.Errorf("log leaks transport detail %q\n  got: %s", unwanted, logged)
		}
	}
}

func TestModifyResponseStripsServerHeader(t *testing.T) {
	upstream := echoUpstream()
	defer upstream.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	resp := doProxyRequest(t, upstream, req)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	if h := resp.Header.Get("Server"); h != "" {
		t.Errorf("Server header not stripped: got %q", h)
	}
}

func TestModifyResponseStripsXPoweredBy(t *testing.T) {
	upstream := echoUpstream()
	defer upstream.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	resp := doProxyRequest(t, upstream, req)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	if h := resp.Header.Get("X-Powered-By"); h != "" {
		t.Errorf("X-Powered-By header not stripped: got %q", h)
	}
}

func TestDefaultTransportConfig(t *testing.T) {
	tc := proxy.DefaultTransportConfig()
	if tc.DialTimeout != 5*time.Second {
		t.Errorf("DialTimeout = %v, want 5s", tc.DialTimeout)
	}
	if tc.ResponseHeaderTimeout != 120*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 120s", tc.ResponseHeaderTimeout)
	}
	if tc.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns = %d, want 100", tc.MaxIdleConns)
	}
}

func TestTracePropagationHeaders(t *testing.T) {
	// Snapshot the global propagator so other tests aren't observably mutated
	// by this one. Without the restore, every test running after this in the
	// same process sees TraceContext{} as the default — generally fine here,
	// but cross-test global state is the kind of land mine that makes
	// failures non-reproducible when test order shifts.
	prevPropagator := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(prevPropagator) })

	// Set up W3C TraceContext propagator (same as production otel.Setup)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"traceparent": r.Header.Get("Traceparent"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	p := proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig())
	srv := httptest.NewServer(p)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/test", http.NoBody)
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body["traceparent"] == "" {
		t.Error("traceparent header not propagated to upstream")
	}
	// The trace ID should be preserved even if span ID changes
	if !strings.Contains(body["traceparent"], "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Errorf("trace ID not preserved: got %q", body["traceparent"])
	}
}

func TestHopByHopHeadersStripped(t *testing.T) {
	// Upstream echoes all headers so we can verify hop-by-hop headers are stripped
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"connection":        r.Header.Get("Connection"),
			"te":                r.Header.Get("Te"),
			"transfer-encoding": r.Header.Get("Transfer-Encoding"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Connection", "keep-alive, X-Custom")
	// "deflate" rather than "trailers" — Go's httputil intentionally re-adds
	// TE: trailers to signal trailer support to backends (stdlib issue 21096).
	req.Header.Set("Te", "deflate")
	req.Header.Set("Transfer-Encoding", "chunked")

	resp := doProxyRequest(t, upstream, req)
	defer func() { _ = resp.Body.Close() }()

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body["connection"] != "" {
		t.Errorf("Connection header not stripped: got %q", body["connection"])
	}
	if body["te"] != "" {
		t.Errorf("Te header not stripped: got %q", body["te"])
	}
	if body["transfer-encoding"] != "" {
		t.Errorf("Transfer-Encoding header not stripped: got %q", body["transfer-encoding"])
	}
}

// TestStreamingFlushesImmediately asserts end-to-end streaming works through
// the proxy: bytes written by upstream reach the client before the upstream
// handler completes. This is the whole reason the proxy sets
// FlushInterval: -1 for MCP streamable-http.
//
// Note on sensitivity: Go's httputil.ReverseProxy auto-upgrades to
// FlushInterval: -1 for any chunked response (ContentLength == -1) or
// Content-Type: text/event-stream, so this test does not distinguish the
// explicit -1 from the default 0. It still guards against regressions that
// would break streaming entirely — e.g., wrapping the body in a buffered
// reader, adding a response-aggregation middleware, or turning off chunked
// encoding upstream. That's the real-world failure mode to catch.
func TestStreamingFlushesImmediately(t *testing.T) {
	release := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream ResponseWriter is not a Flusher")
			return
		}
		// Non-SSE streaming type — avoids Go's SSE auto-upgrade so the test is
		// sensitive to the proxy's FlushInterval setting.
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write([]byte("{\"chunk\":\"first\"}\n")); err != nil {
			t.Errorf("write first chunk: %v", err)
			return
		}
		flusher.Flush()

		// Block until the test has confirmed the first chunk reached the client.
		<-release

		_, _ = w.Write([]byte("{\"chunk\":\"second\"}\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	proxyServer := httptest.NewServer(proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig()))
	defer proxyServer.Close()
	defer close(release) // ensure upstream handler can always finish

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/stream", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read the first chunk off the response body in a goroutine so the main
	// goroutine can enforce a timeout. A buffering proxy would block Read
	// until the upstream completes the whole response.
	type readResult struct {
		line string
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() {
		reader := bufio.NewReader(resp.Body)
		line, err := reader.ReadString('\n')
		readCh <- readResult{line: line, err: err}
	}()

	select {
	case r := <-readCh:
		if r.err != nil {
			t.Fatalf("read first chunk: %v", r.err)
		}
		if !strings.Contains(r.line, "first") {
			t.Fatalf("first chunk = %q, want it to contain \"first\"", r.line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first streamed chunk — FlushInterval may not be forwarding chunks immediately")
	}
}

// TestClientSuppliedXForwardedHeadersNotReflected asserts that a client
// cannot smuggle X-Forwarded-Host / X-Forwarded-Proto / X-Forwarded-For
// values through to the upstream. Go's httputil.ReverseProxy strips these
// from the outbound request before Rewrite runs, and SetXForwarded then
// sets them from r.In.RemoteAddr / r.In.Host / r.In.TLS. A regression to a
// custom proxy implementation that skipped the stripping step would allow
// header smuggling; this test locks the invariant in.
func TestClientSuppliedXForwardedHeadersNotReflected(t *testing.T) {
	var (
		gotXFH   string
		gotXFP   string
		gotXFF   string
		hostSeen string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotXFH = r.Header.Get("X-Forwarded-Host")
		gotXFP = r.Header.Get("X-Forwarded-Proto")
		gotXFF = r.Header.Get("X-Forwarded-For")
		hostSeen = r.Host
	}))
	defer upstream.Close()

	proxyServer := httptest.NewServer(proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig()))
	defer proxyServer.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Attacker-controlled forwarding headers:
	req.Header.Set("X-Forwarded-Host", "admin.internal.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 9.9.9.9")
	req.Header.Set("Forwarded", `for="attacker"; host="evil.example"`)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()

	if gotXFH == "admin.internal.example" {
		t.Errorf("X-Forwarded-Host reflects client-supplied value: %q", gotXFH)
	}
	if gotXFP == "https" {
		t.Errorf("X-Forwarded-Proto reflects client-supplied value: %q", gotXFP)
	}
	if strings.Contains(gotXFF, "8.8.8.8") || strings.Contains(gotXFF, "9.9.9.9") {
		t.Errorf("X-Forwarded-For chain reflects client-supplied entries: %q", gotXFF)
	}
	// httputil also strips the RFC 7239 Forwarded header before Rewrite.
	// There's no API to re-inject it, so it must not appear upstream.
	if got := resp.Header.Get("Forwarded"); got != "" {
		t.Errorf("Forwarded header leaked upstream: %q", got)
	}
	// XFH should be set from r.In.Host, which reflects the proxy-facing
	// hostname — not from the attacker-supplied header.
	if gotXFH == "" {
		t.Error("X-Forwarded-Host empty; expected it to be set from r.In.Host")
	}
	// Upstream's r.Host should be the upstream URL's host, not the client's forged input.
	if hostSeen == "admin.internal.example" {
		t.Errorf("upstream Host header forged by client: %q", hostSeen)
	}
}

func TestCustomTransportConfig_DialTimeout(t *testing.T) {
	tc := proxy.DefaultTransportConfig()
	tc.DialTimeout = time.Nanosecond // Impossibly short

	// Use RFC 5737 TEST-NET address — guaranteed non-routable
	p := proxy.New(mustParseURL(t, "http://192.0.2.1:1"), tc)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502 due to dial timeout, got %d", w.Code)
	}
}

// TestErrorHandlerSeesNoAuthorization locks in the belt-and-suspenders strip:
// Rewrite removes Authorization and Cookie from BOTH r.Out and r.In, so even
// when the upstream is unreachable and the ErrorHandler runs against the
// inbound request, the user JWT cannot leak through a future "log r.Header"
// regression. The proxy is invoked against a non-routable upstream (RFC 5737
// TEST-NET-1), forcing the dial to fail and ErrorHandler to fire. After the
// roundtrip, the original request's Authorization/Cookie headers must be empty.
func TestErrorHandlerSeesNoAuthorization(t *testing.T) {
	tc := proxy.DefaultTransportConfig()
	tc.DialTimeout = time.Nanosecond // Force ErrorHandler

	p := proxy.New(mustParseURL(t, "http://192.0.2.1:1"), tc)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer leaky-jwt")
	req.Header.Set("Cookie", "session=abc123")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
	// httputil.ReverseProxy passes the inbound *http.Request to ErrorHandler.
	// Rewrite must have stripped these from r.In so the ErrorHandler closure
	// (and any future log lines added there) sees no token material.
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization on r.In after Rewrite = %q, want empty (would leak via ErrorHandler logs)", got)
	}
	if got := req.Header.Get("Cookie"); got != "" {
		t.Errorf("Cookie on r.In after Rewrite = %q, want empty", got)
	}
}

// TestRewriteStripsAuthorizationFromInboundRequest covers the success path
// (no error): even when the upstream returns 200, r.In's Authorization header
// must be cleared so any wrapping middleware that logs the inbound request
// after ServeHTTP returns cannot leak the user JWT.
func TestRewriteStripsAuthorizationFromInboundRequest(t *testing.T) {
	upstream := echoUpstream()
	defer upstream.Close()

	p := proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer leaky-jwt")
	req.Header.Set("Cookie", "session=abc123")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization on r.In after Rewrite = %q, want empty", got)
	}
	if got := req.Header.Get("Cookie"); got != "" {
		t.Errorf("Cookie on r.In after Rewrite = %q, want empty", got)
	}
}

// TestResponseBytesObserved asserts ProxyResponseBytes records a sample for a
// completed (non-streaming) response. The exact byte count is not asserted
// here — the histogram surfaces it — but the sample-count delta proves the
// counting body wrapper is wired through ModifyResponse.
func TestResponseBytesObserved(t *testing.T) {
	const payload = "hello, world\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(payload))
	}))
	defer upstream.Close()

	before := histogramSampleCount(t, metrics.ProxyResponseBytes)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	resp := doProxyRequest(t, upstream, req)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if string(body) != payload {
		t.Fatalf("body = %q, want %q", body, payload)
	}

	after := histogramSampleCount(t, metrics.ProxyResponseBytes)
	if after != before+1 {
		t.Fatalf("ProxyResponseBytes sample count = %d, want %d", after, before+1)
	}
}

// counterValue reads the current value of a labelled prometheus counter.
func counterValue(t *testing.T, c interface {
	Write(*dto.Metric) error
},
) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatalf("counter Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

// TestSSEIdleTimeoutClosesStream drives an SSE upstream that sends one event
// and then stalls forever. With a small SSE_IDLE_TIMEOUT, the proxy must
// close the upstream body and increment the idle_timeout disconnect counter.
// This is the resilience M6 guarantee: a silent SSE cannot pin a slot.
func TestSSEIdleTimeoutClosesStream(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream ResponseWriter is not a Flusher")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		// Stall until the test ends.
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()

	tc := proxy.DefaultTransportConfig()
	tc.SSEIdleTimeout = 100 * time.Millisecond

	beforeIdle := counterValue(t, metrics.ProxySSEDisconnectsTotal.WithLabelValues("idle_timeout"))

	p := proxy.New(mustParseURL(t, upstream.URL), tc)
	srv := httptest.NewServer(p)
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/sse", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read until EOF — body should close once the idle timer fires.
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, resp.Body)
		done <- err
	}()

	select {
	case <-done:
		// Stream closed as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not close idle SSE stream within 5s — SSE_IDLE_TIMEOUT not enforced")
	}

	afterIdle := counterValue(t, metrics.ProxySSEDisconnectsTotal.WithLabelValues("idle_timeout"))
	if afterIdle <= beforeIdle {
		t.Fatalf("ProxySSEDisconnectsTotal{reason=idle_timeout} did not increment: before=%v after=%v", beforeIdle, afterIdle)
	}
}

// TestSSEIdleTimeoutDisabled covers the operator escape-hatch: setting
// SSEIdleTimeout to zero disables the idle bound entirely, and a slow stream
// runs to completion (or until the client/upstream ends it) without the
// timer ever firing. This guards against a regression where 0 is mistakenly
// treated as an immediate timeout.
func TestSSEIdleTimeoutDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream ResponseWriter is not a Flusher")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: only\n\n"))
		flusher.Flush()
		// Return immediately — upstream closes the stream cleanly.
	}))
	defer upstream.Close()

	tc := proxy.DefaultTransportConfig()
	tc.SSEIdleTimeout = 0 // disabled

	beforeIdle := counterValue(t, metrics.ProxySSEDisconnectsTotal.WithLabelValues("idle_timeout"))

	p := proxy.New(mustParseURL(t, upstream.URL), tc)
	srv := httptest.NewServer(p)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/sse", http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	afterIdle := counterValue(t, metrics.ProxySSEDisconnectsTotal.WithLabelValues("idle_timeout"))
	if afterIdle != beforeIdle {
		t.Fatalf("idle_timeout counter incremented with SSEIdleTimeout=0: before=%v after=%v", beforeIdle, afterIdle)
	}
}

// mcpHeaderEcho returns an upstream that echoes its entire inbound header map,
// so tests can assert on both header names and values as they arrived.
func mcpHeaderEcho(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(r.Header)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// doMCPHeaderEcho sends req through the proxy to a header-echoing upstream and
// returns the headers the upstream saw.
func doMCPHeaderEcho(t *testing.T, req *http.Request) http.Header {
	t.Helper()
	resp := doProxyRequest(t, mcpHeaderEcho(t), req)
	defer func() { _ = resp.Body.Close() }()

	var got http.Header
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode upstream headers: %v", err)
	}
	return got
}

// TestMCPHeadersForwardedVerbatim pins the transparency contract that MCP
// 2026-07-28 depends on: mcp-gate forwards every Mcp-* request header to
// upstream with its value byte-identical.
//
// The spec mirrors JSON-RPC body fields into HTTP headers (MCP-Protocol-Version,
// Mcp-Method, Mcp-Name, Mcp-Param-*) so intermediaries can route without parsing
// bodies, and requires the origin server to reject a request whose headers
// disagree with its body (400, JSON-RPC -32020 HeaderMismatch). A proxy that
// drops or rewrites one of these headers therefore turns every modern request
// into a HeaderMismatch, and the failure presents as an upstream SDK bug rather
// than a proxy bug. This test exists so a future header allow-list, sanitizer,
// or "strip unknown headers" change fails here first.
//
// We forward these headers by omission — httputil.ReverseProxy copies
// everything that is not hop-by-hop, and proxy.New deliberately deletes only
// Authorization and Cookie. Nothing in the code says "forward Mcp-*", which is
// exactly why the invariant needs a test rather than a comment.
//
// On header NAMES: net/http canonicalizes every inbound field name via
// textproto.CanonicalMIMEHeaderKey before a handler runs, and the original
// bytes are unrecoverable. So `Mcp-Param-userId` reaches upstream as
// `Mcp-Param-Userid`. This is spec-compliant — RFC 9110 and the MCP spec both
// state that field names are case-insensitive — but it is lossy, because the
// spec encodes case-sensitive JSON property names into a case-insensitive
// header name. mcp-gate cannot preserve the original casing without abandoning
// net/http. Do NOT "fix" the assertions below to expect the sent casing; that
// is unsatisfiable, not a bug in this proxy.
func TestMCPHeadersForwardedVerbatim(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
		why    string
	}{
		{
			name:   "protocol version",
			header: "MCP-Protocol-Version",
			value:  "2026-07-28",
			why:    "required on every POST; upstream matches it against _meta",
		},
		{
			name:   "method",
			header: "Mcp-Method",
			value:  "tools/call",
			why:    "required on all requests; mirrors the body's method",
		},
		{
			name:   "name",
			header: "Mcp-Name",
			value:  "list_datasources",
			why:    "required on tools/call, resources/read, prompts/get",
		},
		{
			name:   "name as a resource URI",
			header: "Mcp-Name",
			value:  "file:///projects/myapp/config.json",
			why:    "for resources/read, Mcp-Name carries params.uri",
		},
		{
			name:   "base64 sentinel value",
			header: "Mcp-Param-Greeting",
			value:  "=?base64?SGVsbG8sIOS4lueVjA==?=",
			why:    "the ?= suffix and = padding are what a naive sanitizer mangles",
		},
		{
			name:   "sentinel-encoded name",
			header: "Mcp-Name",
			value:  "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
			why:    "clients must encode any value matching the sentinel pattern",
		},
		{
			name:   "plain param value",
			header: "Mcp-Param-Region",
			value:  "us-west1",
			why:    "the common case: a mirrored tool parameter",
		},
		{
			name:   "value containing spaces",
			header: "Mcp-Param-Text",
			value:  "two words",
			why:    "spaces are legal in a field value and must not be trimmed or split",
		},
		{
			// Removed from the protocol in 2026-07-28 — servers are told to
			// ignore it. Ignoring is upstream's decision, not ours: mcp-gate is
			// transparent, not a protocol filter. Dropping it here would break
			// a legacy client talking to a legacy-capable upstream.
			name:   "session id from a superseded revision",
			header: "Mcp-Session-Id",
			value:  "1868a90c-0d24-45a4-a1a5-2b0a1a5f3b0e",
			why:    "we do not filter headers the origin server is entitled to see",
		},
		{
			name:   "last event id from a superseded revision",
			header: "Last-Event-ID",
			value:  "42",
			why:    "same reasoning; resumability is upstream's call, not ours",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
			req.Header.Set(tt.header, tt.value)

			got := doMCPHeaderEcho(t, req)

			if v := got.Get(tt.header); v != tt.value {
				t.Errorf("%s not forwarded verbatim (%s)\n  sent: %q\n   got: %q",
					tt.header, tt.why, tt.value, v)
			}
		})
	}
}

// TestMcpParamHeadersNotStripped covers the literal requirement that
// "Intermediate servers that do not recognize an Mcp-Param-{Name} header MUST
// forward it and otherwise ignore it." mcp-gate recognizes none of them, so
// every one of these is the unrecognized case.
func TestMcpParamHeadersNotStripped(t *testing.T) {
	sent := map[string]string{
		"Mcp-Param-Region":     "us-west1",
		"Mcp-Param-Query":      "=?base64?c2VsZWN0ICo=?=",
		"Mcp-Param-Limit":      "100",
		"Mcp-Param-DryRun":     "true",
		"Mcp-Param-Unheard-Of": "whatever",
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
	for k, v := range sent {
		req.Header.Set(k, v)
	}

	got := doMCPHeaderEcho(t, req)

	for k, want := range sent {
		if v := got.Get(k); v != want {
			t.Errorf("%s: sent %q, upstream got %q", k, want, v)
		}
	}
}

// TestMcpParamHeaderNameCanonicalized documents the one place where mcp-gate is
// not byte-transparent, and why it cannot be. See the note on header names in
// TestMCPHeadersForwardedVerbatim.
//
// The header is set by direct map assignment rather than Header.Set, because
// Set canonicalizes on write and the mixed-case name would never reach the wire.
func TestMcpParamHeaderNameCanonicalized(t *testing.T) {
	const (
		sentName  = "Mcp-Param-userId"
		canonical = "Mcp-Param-Userid"
		value     = "42"
	)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
	req.Header[sentName] = []string{value}

	got := doMCPHeaderEcho(t, req)

	// Iterating rather than indexing by sentName: a map lookup with a
	// non-canonical key is what staticcheck's SA1008 exists to catch, and it is
	// right in general — the point here is precisely that the key cannot be
	// found that way, which the loop states without looking like a mistake.
	for name := range got {
		if name == sentName {
			t.Errorf("unexpected: %q survived canonicalization. If net/http changed, "+
				"update this test and the note in TestMCPHeadersForwardedVerbatim.", sentName)
		}
	}
	if v := got[canonical]; len(v) != 1 || v[0] != value {
		t.Errorf("value lost along with the casing: %q = %v, want [%q]", canonical, v, value)
	}
}

// TestSSEResponseSetsAccelBuffering covers the MCP 2026-07-28 SHOULD that a
// server initiating an SSE stream sends X-Accel-Buffering: no.
//
// mcp-gate does not buffer — FlushInterval: -1 — but it is not the last proxy
// in the chain, and this header is the conventional instruction to the ones
// downstream. The negative case matters as much as the positive: an
// unconditional Set would put a meaningless header on every JSON response.
func TestSSEResponseSetsAccelBuffering(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        string
	}{
		{"sse response", "text/event-stream", "no"},
		{"sse with charset parameter", "text/event-stream; charset=utf-8", "no"},
		{"uppercase content type still matches", "TEXT/EVENT-STREAM", "no"},
		{"json response is untouched", "application/json", ""},
		{"no content type is untouched", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.contentType != "" {
					w.Header().Set("Content-Type", tt.contentType)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("data: hello\n\n"))
			}))
			defer upstream.Close()

			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", http.NoBody)
			resp := doProxyRequest(t, upstream, req)
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.ReadAll(resp.Body)

			if got := resp.Header.Get("X-Accel-Buffering"); got != tt.want {
				t.Errorf("X-Accel-Buffering = %q, want %q (Content-Type: %q)",
					got, tt.want, tt.contentType)
			}
		})
	}
}

// TestOversizedBodyReturns413 covers the request-size limit reaching the client
// as a client error rather than an upstream one.
//
// The limit is installed by the caller (main.go wraps the body in
// http.MaxBytesReader), but nothing in the handler reads the body — the
// ReverseProxy does, so the read failure surfaces in ErrorHandler. Before this,
// every over-limit request was reported as "the upstream service is
// unavailable": wrong about a healthy upstream, and a false contributor to the
// 5xx-ratio alert.
func TestOversizedBodyReturns413(t *testing.T) {
	const limit = 64

	// Note what this test does NOT claim: that upstream is shielded from the
	// request. httputil.ReverseProxy forwards the headers and then streams the
	// body, so the upstream connection is already open when the limit trips —
	// it sees a request whose body dies mid-stream. Capping the body protects
	// mcp-gate's own memory and gives the client an honest status code; it is
	// not an upstream shield, and MAX_REQUEST_BODY should not be reasoned about
	// as one.
	var upstreamCalled atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled.Store(true)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig())
	limited := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		p.ServeHTTP(w, r)
	})
	front := httptest.NewServer(limited)
	defer front.Close()

	t.Run("over the limit", func(t *testing.T) {
		upstreamCalled.Store(false)
		body := strings.NewReader(strings.Repeat("x", limit*4))
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, front.URL+"/mcp", body)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}

		var decoded map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if decoded["error"] != "payload_too_large" {
			t.Errorf("error = %q, want payload_too_large", decoded["error"])
		}
	})

	t.Run("within the limit still proxies", func(t *testing.T) {
		upstreamCalled.Store(false)
		body := strings.NewReader(strings.Repeat("x", limit/2))
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, front.URL+"/mcp", body)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if !upstreamCalled.Load() {
			t.Error("a request within the limit did not reach upstream")
		}
	})
}
