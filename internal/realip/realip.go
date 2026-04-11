// Package realip extracts the real client IP from HTTP requests.
//
// It trusts X-Real-IP and X-Forwarded-For headers only when the direct
// peer is within a configured trusted CIDR. X-Forwarded-For is walked
// right-to-left, skipping trusted proxy IPs, to prevent spoofing.
// If no trusted proxies are configured, RemoteAddr is always used.
package realip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

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
func Extract(r *http.Request, trustedProxies []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if len(trustedProxies) > 0 {
		remoteIP := net.ParseIP(host)
		if remoteIP != nil && ipInNets(remoteIP, trustedProxies) {
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
				for i := len(ips) - 1; i >= 0; i-- {
					candidate := strings.TrimSpace(ips[i])
					parsed := net.ParseIP(candidate)
					if parsed == nil {
						continue
					}
					if !ipInNets(parsed, trustedProxies) {
						return parsed.String()
					}
				}
			}
			// X-Real-IP fallback: only use if the value is not a
			// trusted proxy. Some reverse proxies set X-Real-IP to
			// the direct peer rather than the resolved client IP.
			if ip := r.Header.Get("X-Real-Ip"); ip != "" {
				if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
					if !ipInNets(parsed, trustedProxies) {
						return parsed.String()
					}
				}
			}
		}
	}

	// Normalize to canonical form so IPv6 representations like
	// "2001:db8:0:0:0:0:0:1" and "2001:db8::1" produce the same
	// string for log keys and metrics labels.
	if parsed := net.ParseIP(host); parsed != nil {
		return parsed.String()
	}
	return host
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRs parses a list of CIDR strings into net.IPNet values.
// Bare IPs without a prefix length are treated as /32 (IPv4) or /128 (IPv6).
func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, entry := range cidrs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP: %q", entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %q: %w", entry, err)
		}
		// Reject catch-all CIDRs (0.0.0.0/0 and ::/0). Trusting every peer
		// defeats the point of TRUSTED_PROXIES and enables IP spoofing via
		// client-supplied X-Forwarded-For / X-Real-IP headers.
		if ones, _ := cidr.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf(
				"refusing catch-all CIDR %q in TRUSTED_PROXIES: "+
					"would trust X-Forwarded-For from every peer and enable IP spoofing",
				entry,
			)
		}
		nets = append(nets, cidr)
	}
	return nets, nil
}
