package ratelimit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/c-premus/mcp-gate/internal/ratelimit"
	"github.com/c-premus/mcp-gate/internal/realip"
)

func mustParseCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	nets, err := realip.ParseCIDRs(cidrs)
	if err != nil {
		t.Fatalf("parse CIDRs: %v", err)
	}
	return nets
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// --- Rate Limiter tests ---

func TestMiddleware_AllowsUnderLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             100,
		Burst:           5,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	})
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	for i := range 5 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, w.Code)
		}
	}
}

func TestMiddleware_RejectsOverLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             1,
		Burst:           3,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	})
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	// First 3 should pass (burst=3)
	for i := range 3 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, w.Code)
		}
	}

	// 4th should be rate limited
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
}

func TestMiddleware_DifferentIPsIndependent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             1,
		Burst:           1,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	})
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	// Exhaust limit for IP A
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("IP A first request: status = %d, want 200", w.Code)
	}

	// IP A should now be limited
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("IP A second request: status = %d, want 429", w.Code)
	}

	// IP B should still work
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.2:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("IP B: status = %d, want 200", w.Code)
	}
}

func TestMiddleware_ReplenishesTokens(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             100, // Fast replenishment for test
		Burst:           1,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	})
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	// Use the single burst token
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200", w.Code)
	}

	// Wait for token replenishment (100 RPS = 10ms per token)
	time.Sleep(20 * time.Millisecond)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("after replenish: status = %d, want 200", w.Code)
	}
}

func TestMiddleware_ResponseFormat(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             1,
		Burst:           0, // Immediately limited
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	})
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	if ra := w.Header().Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["error"] != "rate_limit_exceeded" {
		t.Errorf("error = %q, want rate_limit_exceeded", body["error"])
	}
	if body["error_description"] == "" {
		t.Error("error_description should not be empty")
	}
}

func TestMiddleware_UsesRealIP(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	trusted := mustParseCIDRs(t, "10.0.0.0/8")
	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             1,
		Burst:           1,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
		TrustedProxies:  trusted,
	})
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	// First request from "real" client via trusted proxy
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-Ip", "203.0.113.50")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200", w.Code)
	}

	// Second request from same "real" IP via different proxy port — should be limited
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.2:12345"
	req.Header.Set("X-Real-Ip", "203.0.113.50")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("same real IP via different proxy: status = %d, want 429", w.Code)
	}

	// Different real IP should be allowed
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-Ip", "203.0.113.51")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("different real IP: status = %d, want 200", w.Code)
	}
}

func TestCleanup_EvictsStaleEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             10,
		Burst:           10,
		CleanupInterval: 20 * time.Millisecond,
		StaleAfter:      30 * time.Millisecond,
	})
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	// Generate an entry
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if rl.ClientCount() != 1 {
		t.Fatalf("clients = %d, want 1", rl.ClientCount())
	}

	// Wait for cleanup to evict
	time.Sleep(100 * time.Millisecond)

	if rl.ClientCount() != 0 {
		t.Fatalf("after cleanup: clients = %d, want 0", rl.ClientCount())
	}
}

func TestMiddleware_RejectsWhenMapFull(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rl := ratelimit.New(ctx, ratelimit.Config{
		RPS:             100,
		Burst:           10,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
		MaxClients:      3,
	})
	defer rl.Stop()

	handler := rl.Middleware(okHandler())

	// Fill the map with 3 unique IPs
	for i := range 3 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = fmt.Sprintf("203.0.113.%d:12345", i+1)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("IP %d: status = %d, want 200", i+1, w.Code)
		}
	}

	if rl.ClientCount() != 3 {
		t.Fatalf("clients = %d, want 3", rl.ClientCount())
	}

	// 4th unique IP should be rejected
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.99:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th IP: status = %d, want 429", w.Code)
	}

	// Existing IP should still work
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("existing IP: status = %d, want 200", w.Code)
	}
}

// --- Concurrent Limiter tests ---

func TestConcurrentLimiter_AllowsUnderLimit(t *testing.T) {
	cl := ratelimit.NewConcurrentLimiter(10, 100, nil)
	handler := cl.Middleware(okHandler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestConcurrentLimiter_RejectsOverPerIPLimit(t *testing.T) {
	cl := ratelimit.NewConcurrentLimiter(2, 100, nil)

	block := make(chan struct{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	})
	handler := cl.Middleware(next)

	var wg sync.WaitGroup

	// Start 2 blocking requests
	for range 2 {
		wg.Go(func() {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = "203.0.113.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		})
	}

	// Let goroutines enter the handler
	time.Sleep(50 * time.Millisecond)

	// 3rd request should be rejected
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}

	close(block)
	wg.Wait()
}

func TestConcurrentLimiter_RejectsOverTotalLimit(t *testing.T) {
	cl := ratelimit.NewConcurrentLimiter(100, 2, nil)

	block := make(chan struct{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	})
	handler := cl.Middleware(next)

	var wg sync.WaitGroup

	// Start 2 requests from different IPs to hit total limit
	for i := range 2 {
		wg.Go(func() {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = fmt.Sprintf("203.0.113.%d:12345", i+1)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		})
	}

	time.Sleep(50 * time.Millisecond)

	// 3rd request from a new IP should be rejected (total limit reached)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.99:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}

	close(block)
	wg.Wait()
}

func TestConcurrentLimiter_ReleasesOnCompletion(t *testing.T) {
	cl := ratelimit.NewConcurrentLimiter(1, 100, nil)

	handler := cl.Middleware(okHandler())

	// First request completes immediately
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200", w.Code)
	}

	// Second request should also succeed since first completed
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("second: status = %d, want 200", w.Code)
	}
}

func TestConcurrentLimiter_ResponseFormat(t *testing.T) {
	cl := ratelimit.NewConcurrentLimiter(0, 100, nil) // per-IP limit of 0 = always reject

	handler := cl.Middleware(okHandler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	if ra := w.Header().Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["error"] != "too_many_connections" {
		t.Errorf("error = %q, want too_many_connections", body["error"])
	}
	if body["error_description"] == "" {
		t.Error("error_description should not be empty")
	}
}

func TestConcurrentLimiter_DifferentIPsIndependent(t *testing.T) {
	cl := ratelimit.NewConcurrentLimiter(1, 100, nil)

	block := make(chan struct{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	})
	handler := cl.Middleware(next)

	var wg sync.WaitGroup

	// Block one request from IP A
	wg.Go(func() {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	})

	time.Sleep(50 * time.Millisecond)

	// IP B should still be allowed
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.2:12345"
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		done <- w.Code
	}()

	time.Sleep(50 * time.Millisecond)

	close(block)
	wg.Wait()

	code := <-done
	if code != http.StatusOK {
		t.Fatalf("IP B: status = %d, want 200", code)
	}
}
