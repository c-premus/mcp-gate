package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/c-premus/mcp-gate/internal/ratelimit"
	"github.com/c-premus/mcp-gate/internal/realip"
	"github.com/redis/go-redis/v9"
)

// newClockedRedis starts a miniredis whose TIME is pinned, so GCRA arithmetic
// can be asserted exactly rather than with wall-clock slack.
func newClockedRedis(t *testing.T, now time.Time) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	mr.SetTime(now)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func send(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestRedisLimiter_FractionalRPS pins that RATE_LIMIT_RPS=0.5 means one
// request per two seconds on the Redis backend, as it does in memory. The
// redis_rate backend took an integer rate and was fed math.Ceil(RPS), so it
// enforced 1/s.
func TestRedisLimiter_FractionalRPS(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	mr, client := newClockedRedis(t, start)

	rl := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS: 0.5, Burst: 1, KeyPrefix: "frac:",
	})
	h := realip.Middleware(nil)(rl.Middleware(okHandler()))

	if w := send(t, h); w.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200", w.Code)
	}
	w := send(t, h)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second at t+0: status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After at t+0 = %q, want 2", got)
	}

	// One second later a 1/s limiter would admit; 0.5/s must not.
	mr.SetTime(start.Add(time.Second))
	if w := send(t, h); w.Code != http.StatusTooManyRequests {
		t.Fatalf("at t+1s: status = %d, want 429 (would be 200 if RPS were rounded up)", w.Code)
	}

	mr.SetTime(start.Add(2 * time.Second))
	if w := send(t, h); w.Code != http.StatusOK {
		t.Fatalf("at t+2s: status = %d, want 200", w.Code)
	}
}

// TestRedisLimiter_RefillsAtRate pins the steady state after a burst is
// spent: exactly one more request per emission interval.
func TestRedisLimiter_RefillsAtRate(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	mr, client := newClockedRedis(t, start)

	rl := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS: 2, Burst: 3, KeyPrefix: "refill:",
	})
	h := realip.Middleware(nil)(rl.Middleware(okHandler()))

	for i := range 3 {
		if w := send(t, h); w.Code != http.StatusOK {
			t.Fatalf("burst request %d: status = %d, want 200", i, w.Code)
		}
	}
	if w := send(t, h); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over burst: status = %d, want 429", w.Code)
	}

	mr.SetTime(start.Add(500 * time.Millisecond))
	if w := send(t, h); w.Code != http.StatusOK {
		t.Fatalf("after one interval: status = %d, want 200", w.Code)
	}
	if w := send(t, h); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request in the same interval: status = %d, want 429", w.Code)
	}
}

// TestRedisLimiter_KeyNamespace pins the documented key shape,
// rate:<KeyPrefix><ip>, which the redis_rate backend also used — so keys in a
// running Redis survive the switch and operator tooling keeps working.
func TestRedisLimiter_KeyNamespace(t *testing.T) {
	t.Parallel()
	mr, client := newClockedRedis(t, time.Now())

	rl := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS: 10, Burst: 5, KeyPrefix: "mcpgate:rl:",
	})
	h := realip.Middleware(nil)(rl.Middleware(okHandler()))
	send(t, h)

	if !mr.Exists("rate:mcpgate:rl:203.0.113.1") {
		t.Errorf("bucket key not found; keys = %v", mr.Keys())
	}
	if ttl := mr.TTL("rate:mcpgate:rl:203.0.113.1"); ttl <= 0 {
		t.Errorf("bucket key TTL = %v, want > 0 so idle buckets expire", ttl)
	}
}
