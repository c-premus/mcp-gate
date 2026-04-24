package realip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// Benchmarks for the realip hot path. The post-netip migration goal is
// zero allocations on the common trusted-peer-with-XFF case (production:
// Traefik peer → mcp-gate, XFF carries the real client). Run via:
//
//	go test -bench=. -benchmem -count=5 ./internal/realip/

var (
	benchTrusted = mustParseCIDRsForBench([]string{"172.20.0.0/16", "fd00::/8"})
	// benchSink prevents the compiler from dead-code-eliminating the
	// Extract return value. Assign to it in every benchmark loop.
	benchSink string
)

func mustParseCIDRsForBench(cidrs []string) []netip.Prefix {
	nets, err := ParseCIDRs(cidrs)
	if err != nil {
		panic(err)
	}
	return nets
}

// newBenchRequest constructs a request outside the hot loop so request
// construction cost doesn't show up in the Extract numbers.
func newBenchRequest(remoteAddr, xff, xRealIP string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if xRealIP != "" {
		r.Header.Set("X-Real-Ip", xRealIP)
	}
	return r
}

// BenchmarkExtract_NoTrustedProxies is the bare-minimum path: no trust
// configured, just parse RemoteAddr and return.
func BenchmarkExtract_NoTrustedProxies(b *testing.B) {
	r := newBenchRequest("203.0.113.50:12345", "", "")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchSink = Extract(r, nil)
	}
}

// BenchmarkExtract_UntrustedPeer is the common-internet path: TRUSTED_PROXIES
// is configured but the peer isn't in it, so headers are ignored.
func BenchmarkExtract_UntrustedPeer(b *testing.B) {
	r := newBenchRequest("203.0.113.50:12345", "1.2.3.4", "5.6.7.8")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchSink = Extract(r, benchTrusted)
	}
}

// BenchmarkExtract_TrustedPeer_NoHeaders is the healthz/prometheus probe path:
// peer is in the trusted set but carries no forwarding headers.
func BenchmarkExtract_TrustedPeer_NoHeaders(b *testing.B) {
	r := newBenchRequest("172.20.0.10:54321", "", "")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchSink = Extract(r, benchTrusted)
	}
}

// BenchmarkExtract_TrustedPeer_XFF is the production hot path for real
// client traffic: Traefik resolves the chain into XFF, we walk right-to-left
// and return the first untrusted entry.
func BenchmarkExtract_TrustedPeer_XFF(b *testing.B) {
	r := newBenchRequest(
		"172.20.0.10:54321",
		"203.0.113.50, 172.20.0.5",
		"172.20.0.13",
	)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchSink = Extract(r, benchTrusted)
	}
}

// BenchmarkExtract_TrustedPeer_LongXFF covers the pathological case: many
// hops through trusted proxies. Exercises the right-to-left walk loop.
func BenchmarkExtract_TrustedPeer_LongXFF(b *testing.B) {
	r := newBenchRequest(
		"172.20.0.10:54321",
		"203.0.113.50, 172.20.0.1, 172.20.0.2, 172.20.0.3, 172.20.0.4, 172.20.0.5",
		"",
	)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchSink = Extract(r, benchTrusted)
	}
}

// BenchmarkIPInNets isolates the CIDR-match helper so the Extract numbers
// can be decomposed.
func BenchmarkIPInNets(b *testing.B) {
	ip := netip.MustParseAddr("172.20.0.10")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = ipInNets(ip, benchTrusted)
	}
}

// BenchmarkParseCIDRs covers startup config parsing — not on the hot path,
// but worth tracking so regressions don't silently bloat boot time.
func BenchmarkParseCIDRs(b *testing.B) {
	entries := []string{"172.20.0.0/16", "10.0.0.0/8", "fd00::/8", "192.168.0.0/16"}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = ParseCIDRs(entries)
	}
}
