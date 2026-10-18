package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisKeyNamespace prefixes every bucket key. It is the namespace the
// previous backend (github.com/go-redis/redis_rate) used, kept so the
// documented key shape — rate:<KeyPrefix><ip> — and any keys already in a
// running Redis stay valid across the switch.
const redisKeyNamespace = "rate:"

// limit is one bucket's GCRA parameters: the emission interval (the time
// one request "costs", 1/RPS) and how many requests may arrive at once.
// The interval is a float of seconds, not an integer rate, so a fractional
// RPS such as 0.5 means what it says. redis_rate took an integer rate and
// mcp-gate fed it math.Ceil(RPS), so RATE_LIMIT_RPS=0.5 enforced 1/s on the
// Redis backend and 0.5/s on the in-memory one.
type limit struct {
	burst            int
	emissionInterval float64
}

// newLimit converts the operator-facing RPS and burst into GCRA parameters.
// RedisConfig.Validate guarantees rps > 0.
func newLimit(rps float64, burst int) limit {
	return limit{burst: burst, emissionInterval: 1 / rps}
}

// result is the outcome of one GCRA check.
type result struct {
	allowed    bool
	retryAfter time.Duration
}

// allower is the single operation RedisLimiter needs from its backend.
// Defining it here lets tests inject a fake to exercise the
// error-classification branches without standing up a Redis.
type allower interface {
	Allow(ctx context.Context, key string, l limit) (result, error)
}

// gcraScript is a Generic Cell Rate Algorithm limiter evaluated atomically
// inside Redis: one EVALSHA round trip per request, no read-then-write race
// between replicas.
//
// Ported from github.com/go-redis/redis_rate/v10 (BSD-2-Clause, Copyright (c)
// 2013 The github.com/go-redis/redis_rate Authors), whose script is in turn
// from https://github.com/rwz/redis-gcra (MIT, Copyright (c) 2017 Pavel
// Pravosud). That module has had no release since 2023-04-02; mcp-gate used
// one function from it. Changes from the original:
//
//   - ARGV carries the emission interval directly instead of rate and period,
//     so fractional rates survive (see limit).
//   - Only the single-cost path (allowN with n = 1) is kept, and the script
//     returns just the two values the middleware reads.
//   - The leading redis.replicate_commands() call is gone. Effects
//     replication is the default from Redis 5.0 and the call is a deprecated
//     no-op from Redis 7.0.
//
// The TIME-based epoch shift is unchanged: seconds since 2017-01-01 keep the
// float within double precision until 2048.
var gcraScriptSource = redis.NewScript(`
local rate_limit_key = KEYS[1]
local burst = tonumber(ARGV[1])
local emission_interval = tonumber(ARGV[2])

local burst_offset = emission_interval * burst

local jan_1_2017 = 1483228800
local now = redis.call("TIME")
now = (now[1] - jan_1_2017) + (now[2] / 1000000)

local tat = redis.call("GET", rate_limit_key)
if not tat then
  tat = now
else
  tat = tonumber(tat)
end
tat = math.max(tat, now)

local new_tat = tat + emission_interval
local allow_at = new_tat - burst_offset
local diff = now - allow_at

if diff < 0 then
  return {0, tostring(-diff)}
end

local reset_after = new_tat - now
if reset_after > 0 then
  redis.call("SET", rate_limit_key, new_tat, "EX", math.ceil(reset_after))
end
return {1, "0"}
`)

type gcraScript struct {
	client redis.Scripter
}

// Allow charges one request against key's bucket.
func (g gcraScript) Allow(ctx context.Context, key string, l limit) (result, error) {
	v, err := gcraScriptSource.Run(ctx, g.client,
		[]string{redisKeyNamespace + key},
		l.burst,
		strconv.FormatFloat(l.emissionInterval, 'g', -1, 64),
	).Slice()
	if err != nil {
		return result{}, err
	}
	if len(v) != 2 {
		return result{}, fmt.Errorf("gcra script: expected 2 values, got %d", len(v))
	}
	allowed, ok := v[0].(int64)
	if !ok {
		return result{}, fmt.Errorf("gcra script: allowed is %T, want int64", v[0])
	}
	raw, ok := v[1].(string)
	if !ok {
		return result{}, fmt.Errorf("gcra script: retry_after is %T, want string", v[1])
	}
	retryAfter, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return result{}, fmt.Errorf("gcra script: retry_after: %w", err)
	}
	return result{
		allowed:    allowed == 1,
		retryAfter: time.Duration(retryAfter * float64(time.Second)),
	}, nil
}
