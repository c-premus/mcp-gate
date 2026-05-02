package ratelimit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/c-premus/mcp-gate/internal/ratelimit"
	"github.com/c-premus/mcp-gate/internal/realip"
	"github.com/redis/go-redis/v9"
)

// newMiniredisClient starts an in-process miniredis and returns a connected
// go-redis client. The miniredis is closed by t.Cleanup.
func newMiniredisClient(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestRedisLimiter_AllowsUnderLimit(t *testing.T) {
	t.Parallel()
	client := newMiniredisClient(t)

	rl := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS:       100,
		Burst:     5,
		KeyPrefix: "test:" + t.Name() + ":",
	})
	handler := realip.Middleware(nil)(rl.Middleware(okHandler()))

	for i := range 5 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, w.Code)
		}
	}
}

func TestRedisLimiter_RejectsOverBurst(t *testing.T) {
	t.Parallel()
	client := newMiniredisClient(t)

	rl := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS:       1,
		Burst:     3,
		KeyPrefix: "test:" + t.Name() + ":",
	})
	handler := realip.Middleware(nil)(rl.Middleware(okHandler()))

	for i := range 3 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, w.Code)
		}
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Errorf("missing Retry-After header")
	} else if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want positive integer", ra)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "rate_limit_exceeded" {
		t.Errorf("body.error = %q, want rate_limit_exceeded", body["error"])
	}
}

func TestRedisLimiter_DistinctIPsIndependent(t *testing.T) {
	t.Parallel()
	client := newMiniredisClient(t)

	rl := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS:       1,
		Burst:     2,
		KeyPrefix: "test:" + t.Name() + ":",
	})
	handler := realip.Middleware(nil)(rl.Middleware(okHandler()))

	for range 2 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("IP A: status = %d, want 200", w.Code)
		}
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
	req.RemoteAddr = "198.51.100.1:54321"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("IP B: status = %d, want 200", w.Code)
	}
}

func TestRedisLimiter_KeyPrefixIsolation(t *testing.T) {
	t.Parallel()
	client := newMiniredisClient(t)

	a := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS: 1, Burst: 1, KeyPrefix: "tenant-a:",
	})
	b := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS: 1, Burst: 1, KeyPrefix: "tenant-b:",
	})

	send := func(handler http.Handler) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
		req.RemoteAddr = "203.0.113.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	hA := realip.Middleware(nil)(a.Middleware(okHandler()))
	hB := realip.Middleware(nil)(b.Middleware(okHandler()))

	if got := send(hA); got != http.StatusOK {
		t.Fatalf("tenant-a first: %d", got)
	}
	if got := send(hB); got != http.StatusOK {
		t.Fatalf("tenant-b first (independent bucket): %d", got)
	}
	if got := send(hA); got != http.StatusTooManyRequests {
		t.Fatalf("tenant-a second: %d, want 429", got)
	}
}

func TestRedisConfigValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     ratelimit.RedisConfig
		wantErr bool
	}{
		{"ok", ratelimit.RedisConfig{RPS: 10, Burst: 20}, false},
		{"zero rps", ratelimit.RedisConfig{RPS: 0, Burst: 20}, true},
		{"negative rps", ratelimit.RedisConfig{RPS: -1, Burst: 20}, true},
		{"zero burst", ratelimit.RedisConfig{RPS: 10, Burst: 0}, true},
		{"negative burst", ratelimit.RedisConfig{RPS: 10, Burst: -5}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
