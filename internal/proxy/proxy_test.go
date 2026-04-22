package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

	p := proxy.New(mustParseURL(t, upstream.URL), proxy.DefaultTransportConfig())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "127.0.0.1") || strings.Contains(body, "localhost") {
		t.Errorf("error body leaks internal hostnames: %s", body)
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
