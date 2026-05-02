package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/c-premus/mcp-gate/internal/realip"
	redisrate "github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

// White-box tests covering the error-classification, key-shape, and
// timeout-application paths without standing up a real Redis. Lives in
// `package ratelimit` (not `_test`) so it can use the unexported allower
// interface and newRedisLimiter constructor.

func okStub() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

type fakeAllower struct {
	mu          sync.Mutex
	err         error
	result      *redisrate.Result
	calls       int
	lastKey     string
	lastTimeout time.Duration
	timeoutCtx  bool
}

func (f *fakeAllower) Allow(ctx context.Context, key string, _ redisrate.Limit) (*redisrate.Result, error) {
	f.mu.Lock()
	f.calls++
	f.lastKey = key
	if dl, ok := ctx.Deadline(); ok {
		f.lastTimeout = time.Until(dl)
	}
	timeoutCtx := f.timeoutCtx
	err := f.err
	res := f.result
	f.mu.Unlock()

	if timeoutCtx {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func TestClassifyRedisErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"timeout", context.DeadlineExceeded, "timeout"},
		{"conn refused", syscall.ECONNREFUSED, "unavailable"},
		{"conn reset", syscall.ECONNRESET, "unavailable"},
		{"host unreachable", syscall.EHOSTUNREACH, "unavailable"},
		{"net unreachable", syscall.ENETUNREACH, "unavailable"},
		{"redis closed", redis.ErrClosed, "unavailable"},
		{"random error", errors.New("boom"), "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyRedisErr(tc.err); got != tc.want {
				t.Errorf("classifyRedisErr(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   time.Duration
		want int
	}{
		{-1 * time.Second, 1},
		{0, 1},
		{1 * time.Millisecond, 1},
		{500 * time.Millisecond, 1},
		{1 * time.Second, 1},
		{1500 * time.Millisecond, 2},
		{2 * time.Second, 2},
		{2500 * time.Millisecond, 3},
	}
	for _, tc := range cases {
		if got := retryAfterSeconds(tc.in); got != tc.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestRedisLimiter_FailOpenOnTimeout(t *testing.T) {
	t.Parallel()
	fake := &fakeAllower{timeoutCtx: true}
	rl := newRedisLimiter(fake, RedisConfig{
		RPS: 10, Burst: 20, KeyPrefix: "p:", Timeout: 5 * time.Millisecond,
	})
	handler := realip.Middleware(nil)(rl.Middleware(okStub()))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open)", w.Code)
	}
}

func TestRedisLimiter_FailOpenOnConnRefused(t *testing.T) {
	t.Parallel()
	fake := &fakeAllower{err: syscall.ECONNREFUSED}
	rl := newRedisLimiter(fake, RedisConfig{
		RPS: 10, Burst: 20, KeyPrefix: "p:",
	})
	handler := realip.Middleware(nil)(rl.Middleware(okStub()))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open)", w.Code)
	}
}

func TestRedisLimiter_KeyShape(t *testing.T) {
	t.Parallel()
	fake := &fakeAllower{result: &redisrate.Result{Allowed: 1, Remaining: 19}}
	rl := newRedisLimiter(fake, RedisConfig{
		RPS: 10, Burst: 20, KeyPrefix: "mcpgate:rl:",
	})
	handler := realip.Middleware(nil)(rl.Middleware(okStub()))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.HasPrefix(fake.lastKey, "mcpgate:rl:") {
		t.Errorf("key prefix not applied: got %q", fake.lastKey)
	}
	if !strings.Contains(fake.lastKey, "203.0.113.1") {
		t.Errorf("key missing client IP: got %q", fake.lastKey)
	}
}

func TestRedisLimiter_AppliesTimeout(t *testing.T) {
	t.Parallel()
	fake := &fakeAllower{result: &redisrate.Result{Allowed: 1, Remaining: 19}}
	rl := newRedisLimiter(fake, RedisConfig{
		RPS: 10, Burst: 20, KeyPrefix: "p:", Timeout: 250 * time.Millisecond,
	})
	handler := realip.Middleware(nil)(rl.Middleware(okStub()))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if fake.lastTimeout <= 0 || fake.lastTimeout > 260*time.Millisecond {
		t.Errorf("Allow ctx deadline = %v, want ~250ms", fake.lastTimeout)
	}
}

func TestRedisLimiter_DefaultTimeout(t *testing.T) {
	t.Parallel()
	fake := &fakeAllower{result: &redisrate.Result{Allowed: 1, Remaining: 19}}
	rl := newRedisLimiter(fake, RedisConfig{
		RPS: 10, Burst: 20, KeyPrefix: "p:",
	})
	handler := realip.Middleware(nil)(rl.Middleware(okStub()))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
	req.RemoteAddr = "203.0.113.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if fake.lastTimeout <= 0 || fake.lastTimeout > 110*time.Millisecond {
		t.Errorf("default Allow ctx deadline = %v, want ~100ms", fake.lastTimeout)
	}
}
