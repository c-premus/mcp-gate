// Package ratelimit provides per-IP rate limiting and concurrent request limiting.
//
// Limiter enforces a token-bucket rate limit per client IP with automatic
// cleanup of stale entries. ConcurrentLimiter caps in-flight requests per IP
// and globally. Both resolve client IPs through trusted proxy headers via
// the realip package.
package ratelimit

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/c-premus/mcp-gate/internal/realip"
	"golang.org/x/time/rate"
)

// Config holds rate limiter configuration.
type Config struct {
	RPS             float64       // Requests per second per IP
	Burst           int           // Burst capacity per IP
	CleanupInterval time.Duration // How often to evict stale entries
	StaleAfter      time.Duration // Evict entries not seen for this duration
	TrustedProxies  []*net.IPNet  // For realip.Extract()
	MaxClients      int           // Max tracked IPs (0 = default 100,000)
}

// entry tracks a per-IP rate limiter and last-seen time.
type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Limiter provides per-IP rate limiting with automatic stale entry eviction.
type Limiter struct {
	mu      sync.Mutex
	clients map[string]*entry
	cfg     Config
	cancel  func()
}

const defaultMaxClients = 100_000

// New creates a per-IP rate limiter and starts a background cleanup goroutine.
// The cleanup goroutine stops when ctx is cancelled or Stop() is called.
func New(ctx context.Context, cfg Config) *Limiter {
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = defaultMaxClients
	}
	ctx, cancel := context.WithCancel(ctx)
	l := &Limiter{
		clients: make(map[string]*entry),
		cfg:     cfg,
		cancel:  cancel,
	}
	go l.cleanup(ctx)
	return l
}

// Stop cancels the background cleanup goroutine.
func (l *Limiter) Stop() {
	l.cancel()
}

func (l *Limiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(l.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.mu.Lock()
			now := time.Now()
			for ip, e := range l.clients {
				if now.Sub(e.lastSeen) > l.cfg.StaleAfter {
					delete(l.clients, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}

func (l *Limiter) getLimiter(ip string) (*rate.Limiter, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, exists := l.clients[ip]
	if !exists {
		if len(l.clients) >= l.cfg.MaxClients {
			return nil, false
		}
		e = &entry{
			limiter: rate.NewLimiter(rate.Limit(l.cfg.RPS), l.cfg.Burst),
		}
		l.clients[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter, true
}

// Middleware returns an HTTP middleware that enforces per-IP rate limits.
// Rejected requests receive 429 Too Many Requests with a JSON body.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := realip.Extract(r, l.cfg.TrustedProxies)
		limiter, ok := l.getLimiter(clientIP)

		if !ok {
			metrics.RateLimitedTotal.Inc()
			slog.Warn("rate limiter map full, rejecting new IP",
				"client_ip", clientIP,
				"tracked_clients", l.cfg.MaxClients,
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limit_exceeded","error_description":"Too many requests"}`))
			return
		}

		if !limiter.Allow() {
			metrics.RateLimitedTotal.Inc()
			slog.Warn("rate limited",
				"client_ip", clientIP,
				"path", r.URL.Path,
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limit_exceeded","error_description":"Too many requests"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientCount returns the number of tracked IPs (for testing).
func (l *Limiter) ClientCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}

// ConcurrentLimiter limits the number of concurrent in-flight requests per IP.
type ConcurrentLimiter struct {
	mu             sync.Mutex
	active         map[string]int
	maxPerIP       int
	maxTotal       int
	total          int
	trustedProxies []*net.IPNet
}

// NewConcurrentLimiter creates a concurrent request limiter.
func NewConcurrentLimiter(maxPerIP, maxTotal int, trustedProxies []*net.IPNet) *ConcurrentLimiter {
	return &ConcurrentLimiter{
		active:         make(map[string]int),
		maxPerIP:       maxPerIP,
		maxTotal:       maxTotal,
		trustedProxies: trustedProxies,
	}
}

// Middleware returns an HTTP middleware that enforces per-IP concurrent request limits.
// Rejected requests receive 503 Service Unavailable with a JSON body.
func (cl *ConcurrentLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := realip.Extract(r, cl.trustedProxies)

		cl.mu.Lock()
		if cl.total >= cl.maxTotal || cl.active[clientIP] >= cl.maxPerIP {
			cl.mu.Unlock()
			metrics.ConcurrentLimitedTotal.Inc()
			slog.Warn("concurrent request limit exceeded",
				"client_ip", clientIP,
				"path", r.URL.Path,
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"too_many_connections","error_description":"Too many concurrent requests"}`))
			return
		}
		cl.active[clientIP]++
		cl.total++
		cl.mu.Unlock()

		metrics.ActiveRequests.Inc()

		defer func() {
			cl.mu.Lock()
			cl.active[clientIP]--
			if cl.active[clientIP] == 0 {
				delete(cl.active, clientIP)
			}
			cl.total--
			cl.mu.Unlock()
			metrics.ActiveRequests.Dec()
		}()

		next.ServeHTTP(w, r)
	})
}
