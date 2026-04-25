package ratelimit_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c-premus/mcp-gate/internal/ratelimit"
	"github.com/c-premus/mcp-gate/internal/realip"
)

// Benchmarks for Limiter.Middleware. Rate limiting sits before auth in the
// handler stack, so per-request cost lands on every inbound request — including
// the rejected ones. Run via:
//
//	go test -bench=. -benchmem -count=5 -run=^$ ./internal/ratelimit/

var benchOK = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// newBenchLimiter builds a Limiter wired through realip.Middleware (matching
// production layering) and registers cleanup so each benchmark gets a fresh
// limiter. RPS/Burst are chosen per-benchmark.
func newBenchLimiter(b *testing.B, rps float64, burst int) http.Handler {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)

	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             rps,
		Burst:           burst,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	})
	b.Cleanup(rl.Stop)

	return realip.Middleware(nil)(rl.Middleware(benchOK))
}

// BenchmarkLimiter_SingleClient_UnderLimit measures the steady-state happy
// path: one client, plenty of headroom in the bucket. This is the production
// per-request cost we care about.
func BenchmarkLimiter_SingleClient_UnderLimit(b *testing.B) {
	handler := newBenchLimiter(b, 1_000_000, 1_000_000)

	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkLimiter_SingleClient_OverLimit measures the rejected path. Every
// request hits the 429 branch — verifies the rejected path is no costlier
// than the accepted one, and that no allocations leak from the JSON write.
func BenchmarkLimiter_SingleClient_OverLimit(b *testing.B) {
	// RPS=0.0001 with Burst=1: the first request consumes the only token,
	// every subsequent one is rejected within the benchmark's wall time.
	handler := newBenchLimiter(b, 0.0001, 1)

	// Drain the burst before timing so the first iteration is also rejected.
	{
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkLimiter_ManyClients cycles through 1000 distinct IPs to exercise
// the per-IP map's lookup and insertion paths. The realistic worst case is a
// botnet where each request maps to a different bucket — this isolates the
// map-contention cost from the rate-decision cost.
func BenchmarkLimiter_ManyClients(b *testing.B) {
	handler := newBenchLimiter(b, 1_000_000, 1_000_000)

	const numClients = 1000
	addrs := make([]string, numClients)
	for i := range addrs {
		// 192.0.2.0/24 is the TEST-NET-1 reserved range; values 0-255 fit in
		// the last octet, so cycle through 192.0.2.{i%256} with an additional
		// /16 spread to reach 1000 distinct values.
		addrs[i] = fmt.Sprintf("192.0.%d.%d:12345", i/256, i%256)
	}

	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	i := 0
	for b.Loop() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = addrs[i%numClients]
		handler.ServeHTTP(w, req)
		i++
	}
}
