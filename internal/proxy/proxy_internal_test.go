package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

// White-box tests for the transport-error classifier. Lives in `package proxy`
// (not `proxy_test`) because classifyProxyError is unexported; the rest of the
// package's tests are external. Same split as internal/ratelimit.

func TestClassifyProxyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"context canceled", context.Canceled, "canceled"},
		{"context deadline exceeded", context.DeadlineExceeded, "timeout"},
		{"os deadline exceeded", os.ErrDeadlineExceeded, "timeout"},
		{"connection refused", syscall.ECONNREFUSED, "connection_refused"},
		{
			// Proves unwrapping through the *net.OpError that the dialer
			// actually returns in production, not just the bare errno.
			name: "connection refused wrapped in OpError",
			err:  &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
			want: "connection_refused",
		},
		{"connection reset", syscall.ECONNRESET, "connection_reset"},
		{"net closed", net.ErrClosed, "connection_closed"},
		{"unexpected EOF", io.ErrUnexpectedEOF, "unexpected_eof"},
		{
			name: "DNS not found",
			err:  &net.DNSError{Err: "no such host", Name: "upstream", IsNotFound: true},
			want: "dns_failure",
		},
		{
			// Ordering guard: a *net.DNSError with IsTimeout also satisfies
			// net.Error.Timeout(), so if the generic timeout arm ran first
			// this would be misclassified as "timeout" and a resolver outage
			// would look like a slow upstream.
			name: "DNS timeout classifies as dns_failure, not timeout",
			err:  &net.DNSError{Err: "i/o timeout", Name: "upstream", IsTimeout: true},
			want: "dns_failure",
		},
		{
			// Proves errors.Is unwrapping through fmt.Errorf %w, the shape
			// httputil.ReverseProxy errors arrive in.
			name: "wrapped connection reset",
			err:  fmt.Errorf("proxy roundtrip: %w", syscall.ECONNRESET),
			want: "connection_reset",
		},
		{"unknown", errors.New("boom"), "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyProxyError(tt.err); got != tt.want {
				t.Errorf("classifyProxyError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
