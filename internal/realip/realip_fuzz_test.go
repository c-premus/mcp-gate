package realip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// FuzzExtract exercises the Extract boundary with arbitrary RemoteAddr,
// X-Forwarded-For, and X-Real-IP inputs against a fixed realistic trusted
// proxy set. It locks in three invariants that must hold regardless of input:
//
//   - Extract never panics.
//   - Extract never returns the empty string (downstream consumers rely on
//     the unknownIP sentinel to keep rate-limit buckets stable).
//   - Any non-sentinel return is a valid IP in canonical Unmap() form —
//     re-parsing and re-stringifying yields the same value.
//
// The last invariant catches the netip.Addr gotcha where an IPv4-mapped IPv6
// address (::ffff:1.2.3.4) stringifies verbatim unless Unmap is called, which
// would churn log keys and metric labels if the canonical form ever drifted.
func FuzzExtract(f *testing.F) {
	trusted, err := ParseCIDRs([]string{"172.20.0.0/16", "fd00::/8"})
	if err != nil {
		f.Fatalf("ParseCIDRs: %v", err)
	}

	// Seed corpus spans the interesting cases: untrusted peer, trusted
	// peer with XFF, IPv6, IPv4-mapped IPv6 (exercises Unmap paths),
	// multi-hop XFF, and various degenerate inputs.
	seeds := []struct {
		remoteAddr, xff, xRealIP string
	}{
		{"203.0.113.50:12345", "", ""},
		{"172.20.0.1:54321", "203.0.113.50", ""},
		{"172.20.0.1:54321", "1.2.3.4, 203.0.113.50, 172.20.0.5", ""},
		{"172.20.0.10:54321", "203.0.113.50", "172.20.0.13"},
		{"[2001:db8::1]:12345", "", ""},
		{"[fd00::1]:54321", "2001:db8::99", ""},
		{"[::ffff:203.0.113.50]:12345", "", ""},
		{"172.20.0.1:54321", "::ffff:203.0.113.50", ""},
		{"", "", ""},
		{"@", "", ""},
		{"not-an-address", "", ""},
		{"172.20.0.1:54321", "", "not-an-ip"},
		{"172.20.0.1:54321", "not-an-ip, 203.0.113.50", ""},
	}
	for _, s := range seeds {
		f.Add(s.remoteAddr, s.xff, s.xRealIP)
	}

	f.Fuzz(func(t *testing.T, remoteAddr, xff, xRealIP string) {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		r.RemoteAddr = remoteAddr
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if xRealIP != "" {
			r.Header.Set("X-Real-Ip", xRealIP)
		}

		got := Extract(r, trusted)

		if got == "" {
			t.Fatalf("Extract returned empty string; inputs: remoteAddr=%q xff=%q xRealIP=%q",
				remoteAddr, xff, xRealIP)
		}
		if got == unknownIP {
			return
		}
		parsed, err := netip.ParseAddr(got)
		if err != nil {
			t.Fatalf("Extract returned non-sentinel value %q that does not re-parse as IP (err=%v); inputs: remoteAddr=%q xff=%q xRealIP=%q",
				got, err, remoteAddr, xff, xRealIP)
		}
		// Canonical form check: the return should already be in Unmap form.
		if canonical := parsed.Unmap().String(); canonical != got {
			t.Fatalf("Extract returned non-canonical IP %q (canonical=%q); inputs: remoteAddr=%q xff=%q xRealIP=%q",
				got, canonical, remoteAddr, xff, xRealIP)
		}
	})
}

// FuzzParseCIDRs exercises the config-parse boundary with arbitrary
// comma-separated inputs. Invariants:
//
//   - ParseCIDRs never panics.
//   - On success, every returned prefix has Bits() > 0 (catch-all rejected).
//   - On success, every returned prefix is in masked canonical form — i.e.
//     prefix.String() re-parses to the same prefix, without needing another
//     Masked() call. This locks in the ParsePrefix-doesn't-canonicalize gotcha.
func FuzzParseCIDRs(f *testing.F) {
	seeds := []string{
		"",
		"172.20.0.0/16",
		"172.20.0.0/16,10.0.0.0/8",
		"172.20.0.1",
		"2001:db8::1",
		"fd00::/8",
		"  172.20.0.0/16  ,  ,  10.0.0.0/8  ",
		"0.0.0.0/0",
		"::/0",
		"172.20.0.0/16,0.0.0.0/0",
		"172.20.5.5/16",
		"not-an-ip",
		"172.20.0.0/99",
		"128.0.0.0/1",
		"::ffff:1.2.3.4/128",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, csv string) {
		entries := strings.Split(csv, ",")
		nets, err := ParseCIDRs(entries)
		if err != nil {
			return
		}
		for i, prefix := range nets {
			if prefix.Bits() <= 0 {
				t.Fatalf("ParseCIDRs(%q) returned catch-all prefix at [%d]: %s",
					csv, i, prefix)
			}
			// Round-trip: the returned prefix string must re-parse
			// to the same value. If Masked() were ever dropped,
			// entries like "172.20.5.5/16" would round-trip as-is
			// instead of canonicalizing to "172.20.0.0/16".
			reparsed, perr := netip.ParsePrefix(prefix.String())
			if perr != nil {
				t.Fatalf("ParseCIDRs(%q)[%d]=%s does not re-parse: %v",
					csv, i, prefix, perr)
			}
			if reparsed != prefix {
				t.Fatalf("ParseCIDRs(%q)[%d]=%s not in canonical masked form (reparsed=%s)",
					csv, i, prefix, reparsed)
			}
		}
	})
}
