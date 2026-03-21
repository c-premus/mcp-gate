package realip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mustParseCIDRs is a test helper that calls ParseCIDRs and fails on error.
func mustParseCIDRs(t *testing.T, cidrs []string) []*net.IPNet {
	t.Helper()
	nets, err := ParseCIDRs(cidrs)
	if err != nil {
		t.Fatalf("ParseCIDRs(%v): %v", cidrs, err)
	}
	return nets
}

func TestExtract_NoTrustedProxies(t *testing.T) {
	// Without trusted proxies, always return RemoteAddr regardless of headers.
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "203.0.113.50:12345"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	r.Header.Set("X-Real-Ip", "198.51.100.2")

	got := Extract(r, nil)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50", got)
	}
}

func TestExtract_TrustedProxy_XRealIP(t *testing.T) {
	trusted := mustParseCIDRs(t, []string{"172.20.0.0/16"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "172.20.0.1:54321"
	r.Header.Set("X-Real-Ip", "203.0.113.50")

	got := Extract(r, trusted)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50", got)
	}
}

func TestExtract_TrustedProxy_XRealIP_Priority(t *testing.T) {
	// X-Real-IP should take priority over X-Forwarded-For.
	trusted := mustParseCIDRs(t, []string{"172.20.0.0/16"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "172.20.0.1:54321"
	r.Header.Set("X-Real-Ip", "203.0.113.50")
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 172.20.0.5")

	got := Extract(r, trusted)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50 (X-Real-IP priority)", got)
	}
}

func TestExtract_TrustedProxy_XFF_Simple(t *testing.T) {
	trusted := mustParseCIDRs(t, []string{"172.20.0.0/16"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "172.20.0.1:54321"
	r.Header.Set("X-Forwarded-For", "203.0.113.50")

	got := Extract(r, trusted)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50", got)
	}
}

func TestExtract_TrustedProxy_XFF_RightToLeft(t *testing.T) {
	// Chain: client → proxy1 (trusted) → proxy2 (trusted) → mcp-gate
	// XFF:   "203.0.113.50, 172.20.0.5, 172.20.0.6"
	// Should return 203.0.113.50 (first untrusted from the right).
	trusted := mustParseCIDRs(t, []string{"172.20.0.0/16"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "172.20.0.1:54321"
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 172.20.0.5, 172.20.0.6")

	got := Extract(r, trusted)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50", got)
	}
}

func TestExtract_TrustedProxy_XFF_SpoofPrevention(t *testing.T) {
	// Attacker prepends a fake IP: "1.2.3.4, 203.0.113.50, 172.20.0.5"
	// Walking right-to-left skipping trusted: first untrusted = 203.0.113.50 (real client).
	// The attacker's prepended 1.2.3.4 is ignored.
	trusted := mustParseCIDRs(t, []string{"172.20.0.0/16"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "172.20.0.1:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.50, 172.20.0.5")

	got := Extract(r, trusted)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50 (not spoofed 1.2.3.4)", got)
	}
}

func TestExtract_UntrustedPeer_IgnoresHeaders(t *testing.T) {
	// Peer is NOT trusted — headers must be ignored even if set.
	trusted := mustParseCIDRs(t, []string{"10.0.0.0/8"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "203.0.113.50:12345" // Not in 10.0.0.0/8
	r.Header.Set("X-Real-Ip", "1.2.3.4")
	r.Header.Set("X-Forwarded-For", "5.6.7.8")

	got := Extract(r, trusted)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50 (untrusted peer, headers ignored)", got)
	}
}

func TestExtract_XFF_AllTrusted_FallsBack(t *testing.T) {
	// All IPs in XFF are trusted — should fall back to RemoteAddr.
	trusted := mustParseCIDRs(t, []string{"172.20.0.0/16"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "172.20.0.1:54321"
	r.Header.Set("X-Forwarded-For", "172.20.0.5, 172.20.0.6")

	got := Extract(r, trusted)
	if got != "172.20.0.1" {
		t.Errorf("Extract = %q, want 172.20.0.1 (all XFF trusted, fallback to RemoteAddr)", got)
	}
}

func TestExtract_IPv6(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "[2001:db8::1]:12345"

	got := Extract(r, nil)
	if got != "2001:db8::1" {
		t.Errorf("Extract = %q, want 2001:db8::1", got)
	}
}

func TestExtract_IPv6_Normalization(t *testing.T) {
	// Ensure verbose IPv6 is normalized to canonical form.
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "[2001:0db8:0000:0000:0000:0000:0000:0001]:12345"

	got := Extract(r, nil)
	if got != "2001:db8::1" {
		t.Errorf("Extract = %q, want 2001:db8::1 (normalized)", got)
	}
}

func TestExtract_IPv6_Trusted_XFF(t *testing.T) {
	trusted := mustParseCIDRs(t, []string{"fd00::/8"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "[fd00::1]:54321"
	r.Header.Set("X-Forwarded-For", "2001:db8::99")

	got := Extract(r, trusted)
	if got != "2001:db8::99" {
		t.Errorf("Extract = %q, want 2001:db8::99", got)
	}
}

func TestExtract_XRealIP_InvalidIP(t *testing.T) {
	// Invalid X-Real-IP should fall through to XFF.
	trusted := mustParseCIDRs(t, []string{"172.20.0.0/16"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "172.20.0.1:54321"
	r.Header.Set("X-Real-Ip", "not-an-ip")
	r.Header.Set("X-Forwarded-For", "203.0.113.50")

	got := Extract(r, trusted)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50 (invalid X-Real-IP skipped)", got)
	}
}

func TestExtract_NoHeaders(t *testing.T) {
	// Trusted peer but no forwarding headers — return RemoteAddr.
	trusted := mustParseCIDRs(t, []string{"172.20.0.0/16"})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "172.20.0.1:54321"

	got := Extract(r, trusted)
	if got != "172.20.0.1" {
		t.Errorf("Extract = %q, want 172.20.0.1", got)
	}
}

func TestExtract_RemoteAddrNoPort(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "203.0.113.50" // No port

	got := Extract(r, nil)
	if got != "203.0.113.50" {
		t.Errorf("Extract = %q, want 203.0.113.50", got)
	}
}

// --- ParseCIDRs tests ---

func TestParseCIDRs_Empty(t *testing.T) {
	nets, err := ParseCIDRs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nets != nil {
		t.Errorf("expected nil, got %v", nets)
	}
}

func TestParseCIDRs_CIDR(t *testing.T) {
	nets, err := ParseCIDRs([]string{"172.20.0.0/16", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("expected 2 nets, got %d", len(nets))
	}
	if nets[0].String() != "172.20.0.0/16" {
		t.Errorf("nets[0] = %s, want 172.20.0.0/16", nets[0])
	}
}

func TestParseCIDRs_BareIPv4(t *testing.T) {
	nets, err := ParseCIDRs([]string{"172.20.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
	if nets[0].String() != "172.20.0.1/32" {
		t.Errorf("nets[0] = %s, want 172.20.0.1/32", nets[0])
	}
}

func TestParseCIDRs_BareIPv6(t *testing.T) {
	nets, err := ParseCIDRs([]string{"2001:db8::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
	if nets[0].String() != "2001:db8::1/128" {
		t.Errorf("nets[0] = %s, want 2001:db8::1/128", nets[0])
	}
}

func TestParseCIDRs_Whitespace(t *testing.T) {
	nets, err := ParseCIDRs([]string{"  172.20.0.0/16  ", "", "  "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net (empty entries skipped), got %d", len(nets))
	}
}

func TestParseCIDRs_InvalidIP(t *testing.T) {
	_, err := ParseCIDRs([]string{"not-an-ip"})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestParseCIDRs_InvalidCIDR(t *testing.T) {
	_, err := ParseCIDRs([]string{"172.20.0.0/99"})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
