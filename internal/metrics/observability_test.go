package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestTrustedProxyCIDRsGauge verifies the gauge accepts both the empty-list
// (gauge=0, the dev/test default) and a populated list (gauge=2). The gauge is
// set once at startup from cmd/mcp-gate/main.go::run() — this test exercises
// only the metric vector, not the run() wiring (which lives behind the cmd
// package's own test suite).
func TestTrustedProxyCIDRsGauge(t *testing.T) {
	tests := []struct {
		name string
		set  float64
		want float64
	}{
		{"empty TRUSTED_PROXIES", 0, 0},
		{"two CIDRs", 2, 2},
		{"large list", 17, 17},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			TrustedProxyCIDRs.Set(tt.set)
			if got := testutil.ToFloat64(TrustedProxyCIDRs); got != tt.want {
				t.Errorf("TrustedProxyCIDRs = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestJWKSPollErrorsCounterMonotonic asserts the counter is registered, accepts
// increments, and is monotonic (Counter contract). This is a smoke test for
// the metric definition itself; the integration with auth.pollJWKSMetrics is
// covered in internal/auth/poll_metrics_test.go.
func TestJWKSPollErrorsCounterMonotonic(t *testing.T) {
	before := testutil.ToFloat64(JWKSPollErrorsTotal)
	JWKSPollErrorsTotal.Inc()
	JWKSPollErrorsTotal.Inc()
	if got := testutil.ToFloat64(JWKSPollErrorsTotal) - before; got != 2 {
		t.Errorf("JWKSPollErrorsTotal increment = %v, want 2", got)
	}
}

// TestOTELSpansDroppedTotalRegistered ensures the placeholder counter is wired
// up and zero-valued. Until the OTel SDK exposes a public hook for queue-full
// drops (resilience M5), this counter is documented as always-zero, but it
// must still be discoverable via /metrics so the dashboard panel renders.
func TestOTELSpansDroppedTotalRegistered(t *testing.T) {
	if got := testutil.ToFloat64(OTELSpansDroppedTotal); got != 0 {
		t.Errorf("OTELSpansDroppedTotal = %v, want 0 (placeholder)", got)
	}
}
