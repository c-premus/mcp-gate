// Package realip extracts the real client IP from HTTP requests.
//
// It trusts X-Real-IP and X-Forwarded-For headers only when the direct
// peer is within a configured trusted CIDR. X-Forwarded-For is walked
// right-to-left, skipping trusted proxy IPs, to prevent spoofing.
// If no trusted proxies are configured, RemoteAddr is always used.
package realip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// ipContextKey is the context key for the extracted client IP.
type ipContextKey struct{}

// FromContext returns the client IP previously stored by Middleware.
// If no IP is in the context, it returns an empty string.
func FromContext(r *http.Request) string {
	if ip, ok := r.Context().Value(ipContextKey{}).(string); ok {
		return ip
	}
	return ""
}

// Middleware returns HTTP middleware that calls Extract once and stores the
// result in the request context. Downstream handlers use FromContext to
// retrieve the IP without re-parsing headers.
func Middleware(trustedProxies []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := Extract(r, trustedProxies)
			ctx := context.WithValue(r.Context(), ipContextKey{}, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// unknownIP is returned when the request has no parseable remote address.
// Using a sentinel instead of "" keeps rate-limit bucket keys stable for
// downstream consumers — otherwise every anomalous request would share the
// empty-string bucket, giving one misbehaving client a lever to DoS all
// unresolvable requests. In practice Go's HTTP server always populates
// RemoteAddr, so this sentinel is strictly defense-in-depth.
const unknownIP = "unknown"

// Extract returns the real client IP for the given request. When the
// direct peer (RemoteAddr) falls within a trusted proxy CIDR, it checks
// X-Forwarded-For and X-Real-IP headers. Otherwise it returns RemoteAddr
// only, preventing IP spoofing via header manipulation.
//
// X-Forwarded-For is checked first because reverse proxies like Traefik
// resolve the trust chain and place the real client IP there. X-Real-IP
// is a fallback — some proxies (e.g. Traefik) set it to the direct peer
// (a proxy IP), not the end client. In both cases, IPs that fall within
// trusted proxy CIDRs are skipped to avoid returning a proxy address.
//
// Extract never returns the empty string: an unparseable or absent
// RemoteAddr maps to the unknownIP sentinel.
func Extract(r *http.Request, trustedProxies []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		return unknownIP
	}

	if len(trustedProxies) > 0 {
		remoteIP, _ := netip.ParseAddr(host)
		if remoteIP.IsValid() && ipInNets(remoteIP, trustedProxies) {
			// X-Forwarded-For: walk right-to-left, skip trusted proxies.
			// The first untrusted IP is the real client. This prevents
			// spoofing via attacker-prepended entries at the front.
			//
			// Some proxies emit XFF as multiple separate header instances
			// rather than a single comma-joined value. Header.Values()
			// collects all of them in arrival order so the right-to-left
			// walk sees the full chain.
			if xffs := r.Header.Values("X-Forwarded-For"); len(xffs) > 0 {
				xff := strings.Join(xffs, ",")
				ips := strings.Split(xff, ",")
				for _, ip := range slices.Backward(ips) {
					candidate := strings.TrimSpace(ip)
					parsed, _ := netip.ParseAddr(candidate)
					if !parsed.IsValid() {
						continue
					}
					if !ipInNets(parsed, trustedProxies) {
						return parsed.Unmap().String()
					}
				}
			}
			// X-Real-IP fallback: only use if the value is not a
			// trusted proxy. Some reverse proxies set X-Real-IP to
			// the direct peer rather than the resolved client IP.
			if ip := r.Header.Get("X-Real-Ip"); ip != "" {
				if parsed, _ := netip.ParseAddr(strings.TrimSpace(ip)); parsed.IsValid() {
					if !ipInNets(parsed, trustedProxies) {
						return parsed.Unmap().String()
					}
				}
			}
		}
	}

	// Normalize to canonical form so IPv6 representations like
	// "2001:db8:0:0:0:0:0:1" and "2001:db8::1" produce the same
	// string for log keys and metrics labels. Unmap collapses
	// IPv4-mapped IPv6 (::ffff:1.2.3.4) to its IPv4 string form.
	if parsed, _ := netip.ParseAddr(host); parsed.IsValid() {
		return parsed.Unmap().String()
	}
	// Unparseable host (e.g. Unix socket "@", or a bare hostname): fall
	// through to the sentinel rather than reflecting attacker-shaped junk
	// into metric labels or log keys.
	return unknownIP
}

// ipInNets reports whether ip is contained in any of the given prefixes.
// It calls Unmap on ip so that IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
// are matched against IPv4 prefixes — netip.Prefix.Contains otherwise
// rejects family mismatches.
func ipInNets(ip netip.Addr, nets []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRs parses a list of CIDR strings into netip.Prefix values.
// Bare IPs without a prefix length are treated as /32 (IPv4) or /128 (IPv6).
func ParseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	nets := make([]netip.Prefix, 0, len(cidrs))
	for _, entry := range cidrs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var prefix netip.Prefix
		if strings.Contains(entry, "/") {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %q: %w", entry, err)
			}
			// Masked() canonicalizes to the network address so
			// String() output matches the old net.ParseCIDR behavior
			// (which always returned the masked form).
			prefix = p.Masked()
		} else {
			addr, err := netip.ParseAddr(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid IP: %q", entry)
			}
			// BitLen() is 32 for IPv4, 128 for IPv6.
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		// Reject catch-all CIDRs (0.0.0.0/0 and ::/0). Trusting every peer
		// defeats the point of TRUSTED_PROXIES and enables IP spoofing via
		// client-supplied X-Forwarded-For / X-Real-IP headers.
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf(
				"refusing catch-all CIDR %q in TRUSTED_PROXIES: "+
					"would trust X-Forwarded-For from every peer and enable IP spoofing",
				entry,
			)
		}
		nets = append(nets, prefix)
	}
	return nets, nil
}
