//go:build integration

package ratelimit_test

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c-premus/mcp-gate/internal/ratelimit"
	"github.com/c-premus/mcp-gate/internal/realip"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

var (
	testRedisClient *redis.Client
	testRedisAddr   string
	testRedisCtr    testcontainers.Container
)

// TestMain spins up a real Redis container shared by every integration test
// in this package. If docker is not available the suite skips with exit 0
// (so `go test -tags integration ./...` is safe in environments where docker
// has not been wired up).
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("docker"); err != nil {
		log.Printf("skipping integration tests: docker not found in PATH")
		os.Exit(0)
	}

	ctx := context.Background()

	container, err := tcredis.Run(ctx, "redis:8-alpine")
	if err != nil {
		log.Printf("skipping integration tests: starting redis container: %v", err)
		os.Exit(0)
	}
	testRedisCtr = container

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		log.Fatalf("getting redis connection string: %v", err)
	}

	opts, err := redis.ParseURL(connStr)
	if err != nil {
		log.Fatalf("parsing redis URL: %v", err)
	}
	testRedisAddr = opts.Addr

	testRedisClient = redis.NewClient(opts)
	if err := testRedisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("pinging redis: %v", err)
	}

	code := m.Run()

	_ = testRedisClient.Close()
	if err := testcontainers.TerminateContainer(container); err != nil {
		log.Printf("terminating redis container: %v", err)
	}
	os.Exit(code)
}

// TestIntegration_CrossInstanceEnforcement is the load-bearing test for this
// whole change. Two RedisLimiter instances against the same Redis must
// enforce a shared bucket — otherwise horizontal scaling silently multiplies
// the configured per-IP RPS by N replicas.
func TestIntegration_CrossInstanceEnforcement(t *testing.T) {
	keyPrefix := "test:cross:" + t.Name() + ":"
	t.Cleanup(func() { _ = clearKeys(keyPrefix) })

	const burst = 5
	cfg := ratelimit.RedisConfig{RPS: 1, Burst: burst, KeyPrefix: keyPrefix}
	a := ratelimit.NewRedisLimiter(testRedisClient, cfg)
	b := ratelimit.NewRedisLimiter(testRedisClient, cfg)

	hA := realip.Middleware(nil)(a.Middleware(okHandler()))
	hB := realip.Middleware(nil)(b.Middleware(okHandler()))

	send := func(handler http.Handler) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
		req.RemoteAddr = "203.0.113.42:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	allowed := 0
	for i := 0; i < burst*2; i++ {
		var code int
		if i%2 == 0 {
			code = send(hA)
		} else {
			code = send(hB)
		}
		if code == http.StatusOK {
			allowed++
		}
	}

	if allowed > burst {
		t.Fatalf("combined allowed=%d across both instances, want <= burst (%d)", allowed, burst)
	}
}

func TestIntegration_DistinctIPsIndependent(t *testing.T) {
	keyPrefix := "test:distinct:" + t.Name() + ":"
	t.Cleanup(func() { _ = clearKeys(keyPrefix) })

	rl := ratelimit.NewRedisLimiter(testRedisClient, ratelimit.RedisConfig{
		RPS: 1, Burst: 1, KeyPrefix: keyPrefix,
	})
	h := realip.Middleware(nil)(rl.Middleware(okHandler()))

	send := func(remoteAddr string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if got := send("203.0.113.1:1"); got != http.StatusOK {
		t.Fatalf("IP A first: %d", got)
	}
	if got := send("203.0.113.1:2"); got != http.StatusTooManyRequests {
		t.Fatalf("IP A second: %d, want 429", got)
	}
	if got := send("198.51.100.1:1"); got != http.StatusOK {
		t.Fatalf("IP B first (independent bucket): %d, want 200", got)
	}
}

func TestIntegration_FailOpenWhenRedisDown(t *testing.T) {
	// Stand up an isolated Redis we can drop while the limiter is mid-flight.
	ctx := context.Background()
	side, err := tcredis.Run(ctx, "redis:8-alpine")
	if err != nil {
		t.Skipf("starting side redis container: %v", err)
	}
	t.Cleanup(func() {
		// Container may already be terminated; ignore that error.
		_ = testcontainers.TerminateContainer(side)
	})

	connStr, err := side.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	opts, err := redis.ParseURL(connStr)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })

	rl := ratelimit.NewRedisLimiter(client, ratelimit.RedisConfig{
		RPS: 10, Burst: 20, KeyPrefix: "test:fo:" + t.Name() + ":", Timeout: 200 * time.Millisecond,
	})

	var passed int32
	h := realip.Middleware(nil)(rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&passed, 1)
		w.WriteHeader(http.StatusOK)
	})))

	send := func() int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", http.NoBody)
		req.RemoteAddr = "203.0.113.99:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if got := send(); got != http.StatusOK {
		t.Fatalf("baseline request before Redis down: %d, want 200", got)
	}

	// Stop the Redis container — subsequent Allow calls must fail open.
	if err := testcontainers.TerminateContainer(side); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("terminating side container: %v", err)
	}

	if got := send(); got != http.StatusOK {
		t.Fatalf("post-down request: %d, want 200 (fail-open)", got)
	}
	if atomic.LoadInt32(&passed) < 2 {
		t.Fatalf("handler invoked %d times, want >= 2 (fail-open path)", passed)
	}
}

// clearKeys deletes all rate: prefixed keys under the given prefix so a
// repeated `go test -count=N` run is not contaminated by leftover state.
// redis_rate prepends "rate:" to every key, so the SCAN pattern is
// rate:<prefix>*.
func clearKeys(prefix string) error {
	ctx := context.Background()
	pattern := "rate:" + prefix + "*"
	iter := testRedisClient.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		_ = testRedisClient.Del(ctx, iter.Val()).Err()
	}
	return iter.Err()
}
