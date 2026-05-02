package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"syscall"
	"time"

	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/c-premus/mcp-gate/internal/realip"
	redisrate "github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

// RedisConfig holds Redis-backed rate limiter configuration.
//
// RPS and Burst share semantics with the in-memory Limiter Config so operators
// can switch backends without re-tuning. KeyPrefix is concatenated with the
// client IP to form the bucket key (the redis_rate library further prepends
// its own "rate:" namespace, so the final Redis key is rate:<KeyPrefix><ip>).
//
// Timeout bounds each Allow call against Redis. Beyond it the request fails
// open: the request is forwarded to next, the timeout/unavailable counter
// increments, and the proxy keeps serving traffic. A short default (100ms)
// keeps Redis from becoming a hot-path latency dependency.
type RedisConfig struct {
	RPS       float64
	Burst     int
	KeyPrefix string
	Timeout   time.Duration
}

// allower is the subset of redis_rate.Limiter we depend on. Defining it here
// (rather than taking *redis_rate.Limiter directly) lets tests inject a fake
// to exercise the error-classification branches without standing up a Redis.
type allower interface {
	Allow(ctx context.Context, key string, limit redisrate.Limit) (*redisrate.Result, error)
}

// RedisLimiter enforces a per-IP rate limit backed by Redis. Multiple replicas
// sharing one Redis instance enforce the configured RPS globally per IP.
type RedisLimiter struct {
	limiter   allower
	limit     redisrate.Limit
	keyPrefix string
	timeout   time.Duration
}

// NewRedisLimiter constructs a RedisLimiter from a redis client.
// The caller is responsible for the client's lifecycle (Close on shutdown).
func NewRedisLimiter(client redis.UniversalClient, cfg RedisConfig) *RedisLimiter {
	return newRedisLimiter(redisrate.NewLimiter(client), cfg)
}

func newRedisLimiter(l allower, cfg RedisConfig) *RedisLimiter {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 100 * time.Millisecond
	}
	return &RedisLimiter{
		limiter: l,
		limit: redisrate.Limit{
			Rate:   int(math.Ceil(cfg.RPS)),
			Burst:  cfg.Burst,
			Period: time.Second,
		},
		keyPrefix: cfg.KeyPrefix,
		timeout:   cfg.Timeout,
	}
}

// Middleware returns an HTTP middleware that enforces per-IP rate limits via
// Redis. On Redis-side errors the request fails open with a metric increment;
// the proxy must keep serving traffic when Redis is degraded.
func (r *RedisLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		clientIP := realip.FromContext(req)
		key := r.keyPrefix + clientIP

		ctx, cancel := context.WithTimeout(req.Context(), r.timeout)
		start := time.Now()
		res, err := r.limiter.Allow(ctx, key, r.limit)
		metrics.RateLimitRedisLatency.Observe(time.Since(start).Seconds())
		cancel()

		if err != nil {
			metrics.RateLimitRedisErrorsTotal.WithLabelValues(classifyRedisErr(err)).Inc()
			slog.Debug("redis rate-limit failed open",
				"client_ip", clientIP,
				"err", err,
			)
			next.ServeHTTP(w, req)
			return
		}

		if res.Allowed <= 0 {
			metrics.RateLimitedTotal.Inc()
			retryAfter := retryAfterSeconds(res.RetryAfter)
			slog.Debug("rate limited (redis)",
				"client_ip", clientIP,
				"path", req.URL.Path,
				"retry_after_s", retryAfter,
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limit_exceeded","error_description":"Too many requests"}`))
			return
		}

		next.ServeHTTP(w, req)
	})
}

// classifyRedisErr buckets a Redis call error into a fixed-cardinality label
// for the mcpgate_ratelimit_redis_errors_total counter.
func classifyRedisErr(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH):
		return "unavailable"
	case errors.Is(err, redis.ErrClosed):
		return "unavailable"
	default:
		return "other"
	}
}

// retryAfterSeconds rounds a redis_rate retry-after duration up to whole
// seconds with a floor of 1, matching the Retry-After header convention used
// by the in-memory Limiter for parity across backends.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		return 1
	}
	return s
}

// Validate returns an error if the config has obvious issues.
func (c RedisConfig) Validate() error {
	if c.RPS <= 0 {
		return fmt.Errorf("redis rate limit RPS must be positive, got %f", c.RPS)
	}
	if c.Burst <= 0 {
		return fmt.Errorf("redis rate limit burst must be positive, got %d", c.Burst)
	}
	return nil
}
