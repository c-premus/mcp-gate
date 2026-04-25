package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// errStorage embeds jwkset.MemoryJWKSet and overrides KeyReadAll so the poll
// goroutine sees a configurable error sequence without needing the full
// 9-method Storage interface implemented by hand.
type errStorage struct {
	*jwkset.MemoryJWKSet
	calls    atomic.Int64
	failUpTo int64 // calls 1..failUpTo return errFakeRead; subsequent calls succeed.
}

var errFakeRead = errors.New("fake storage read failure")

func (e *errStorage) KeyReadAll(ctx context.Context) ([]jwkset.JWK, error) {
	n := e.calls.Add(1)
	if n <= e.failUpTo {
		return nil, errFakeRead
	}
	return e.MemoryJWKSet.KeyReadAll(ctx)
}

// TestPollJWKSMetrics_ReadErrorIncrementsCounter exercises the error branch of
// pollJWKSMetrics. Two ticks of failures should bump
// mcpgate_jwks_poll_errors_total by 2 without leaving the goroutine wedged.
func TestPollJWKSMetrics_ReadErrorIncrementsCounter(t *testing.T) {
	mem := jwkset.NewMemoryStorage()
	storage := &errStorage{MemoryJWKSet: mem, failUpTo: 100} // always fail

	before := testutil.ToFloat64(metrics.JWKSPollErrorsTotal)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		pollJWKSMetrics(ctx, storage, "", 20*time.Millisecond)
	}()

	// Wait until at least 2 ticks recorded an error, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if storage.calls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pollJWKSMetrics did not exit after ctx cancel")
	}

	got := testutil.ToFloat64(metrics.JWKSPollErrorsTotal) - before
	if got < 2 {
		t.Errorf("JWKSPollErrorsTotal increment = %v, want >= 2", got)
	}
}

// TestPollJWKSMetrics_WarnAfterThreshold asserts the consecutive-failure
// counter reaches at least pollErrWarnThreshold before the goroutine exits.
// The goroutine logs at Warn at and beyond the threshold; we observe the
// state machine indirectly via the metrics counter (which increments on every
// failure) — once the increment count meets the threshold the Warn branch has
// fired. This avoids attaching a slog handler in tests, which would interfere
// with parallel runs that share slog.Default().
func TestPollJWKSMetrics_WarnAfterThreshold(t *testing.T) {
	mem := jwkset.NewMemoryStorage()
	storage := &errStorage{MemoryJWKSet: mem, failUpTo: 100}

	before := testutil.ToFloat64(metrics.JWKSPollErrorsTotal)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		pollJWKSMetrics(ctx, storage, "", 10*time.Millisecond)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if testutil.ToFloat64(metrics.JWKSPollErrorsTotal)-before >= float64(pollErrWarnThreshold) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	got := testutil.ToFloat64(metrics.JWKSPollErrorsTotal) - before
	if got < float64(pollErrWarnThreshold) {
		t.Fatalf("expected >= %d consecutive failures recorded, got %v", pollErrWarnThreshold, got)
	}
}

// TestPollJWKSMetrics_SuccessResetsConsecutiveCounter exercises the recovery
// path: after one failure, a successful read resets the consecutive counter,
// and the gauge is updated with the current key count.
func TestPollJWKSMetrics_SuccessResetsConsecutiveCounter(t *testing.T) {
	mem := jwkset.NewMemoryStorage()
	storage := &errStorage{MemoryJWKSet: mem, failUpTo: 1} // first call fails, then succeeds.

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	beforePoll := testutil.ToFloat64(metrics.JWKSPollErrorsTotal)

	done := make(chan struct{})
	go func() {
		defer close(done)
		pollJWKSMetrics(ctx, storage, "", 10*time.Millisecond)
	}()

	// Wait for at least 3 calls (1 fail, 2+ success) so the success path executes.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if storage.calls.Load() >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	// Exactly one error should have been observed (failUpTo=1).
	gotErrs := testutil.ToFloat64(metrics.JWKSPollErrorsTotal) - beforePoll
	if gotErrs != 1 {
		t.Errorf("expected exactly 1 poll error, got %v", gotErrs)
	}
}
