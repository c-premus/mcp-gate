// Package realip extracts the real client IP from HTTP requests,
// accounting for trusted reverse proxies that set X-Real-IP and
// X-Forwarded-For headers.
package realip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Extract returns the real client IP for the given request. When the
// direct peer (RemoteAddr) falls within a trusted proxy CIDR, it checks
// X-Real-IP and X-Forwarded-For headers. Otherwise it returns RemoteAddr
// only, preventing IP spoofing via header manipulation.
func Extract(r *http.Request, trustedProxies []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if len(trustedProxies) > 0 {
		remoteIP := net.ParseIP(host)
		if remoteIP != nil && ipInNets(remoteIP, trustedProxies) {
			// X-Real-IP takes priority (single IP set by the proxy).
			if ip := r.Header.Get("X-Real-Ip"); ip != "" {
				if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
					return parsed.String()
				}
			}
			// X-Forwarded-For: walk right-to-left, skip trusted proxies.
			// The first untrusted IP is the real client. This prevents
			// spoofing via attacker-prepended entries at the front.
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
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
		nets = append(nets, cidr)
	}
	return nets, nil
}
