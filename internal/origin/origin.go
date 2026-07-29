// Package origin implements opt-in Origin header validation.
//
// MCP 2026-07-28 Streamable HTTP: "Servers MUST validate the Origin header on
// all incoming connections to prevent DNS rebinding attacks. If the Origin
// header is present and invalid, servers MUST respond with HTTP 403 Forbidden."
//
// This is opt-in and disabled by default, and that is a deliberate reading of
// the requirement rather than a shortcut.
//
// DNS rebinding targets a server reachable at a name the attacker can re-point
// — canonically a loopback-bound one, which is why the same spec section pairs
// the requirement with "when running locally, servers SHOULD bind only to
// localhost". A public HTTPS origin behind a real certificate cannot be
// rebound, and a cross-origin browser cannot read its responses anyway unless
// the server sends CORS headers, which mcp-gate does not.
//
// Against that, enabling it blindly is dangerous in a specific way: an MCP
// client's Origin behavior is not contractually documented and can change
// without notice, and a wrong allow-list produces 403 on every request while
// /healthz stays green — so container health checks pass, deploy smoke tests
// pass, and automatic rollback never fires. The failure is total and silent.
//
// So: implemented for the deployments that are in the threat model (mcp-gate
// fronting a LAN- or loopback-adjacent MCP server), off for the ones that are
// not.
package origin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/c-premus/mcp-gate/internal/metrics"
	"github.com/c-premus/mcp-gate/internal/realip"
)

// nullOrigin is RFC 6454's serialization of an opaque origin. Browsers send it
// from sandboxed iframes, some redirect chains, and file:// documents.
const nullOrigin = "null"

// ErrNullOrigin is returned by Parse when the allow-list contains "null".
var ErrNullOrigin = errors.New(
	`"null" cannot be allow-listed: it is the opaque origin (RFC 6454 §6), ` +
		`shared by every sandboxed iframe and file:// document, so allowing it ` +
		`grants access to contexts you cannot identify`)

// Parse validates and canonicalizes a list of allowed origins. An empty or
// all-blank list returns nil, which callers treat as "validation disabled".
//
// Refusing "null" at parse time follows realip.ParseCIDRs refusing 0.0.0.0/0:
// an operator almost never means it, and a loud startup error beats a silent
// hole.
func Parse(origins []string) ([]string, error) {
	if len(origins) == 0 {
		return nil, nil
	}

	out := make([]string, 0, len(origins))
	for _, raw := range origins {
		o := strings.TrimSpace(raw)
		if o == "" {
			continue
		}
		if strings.EqualFold(o, nullOrigin) {
			return nil, ErrNullOrigin
		}
		canonical, err := canonicalize(o)
		if err != nil {
			return nil, fmt.Errorf("allowed origin %q: %w", raw, err)
		}
		out = append(out, canonical)
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// canonicalize reduces an origin to scheme://host[:port] with scheme and host
// lowercased, and rejects anything that is not a serialized origin.
//
// Rejecting rather than trimming a path, query, or userinfo is intentional: a
// value like "https://claude.ai/api" means the operator pasted a URL where an
// origin belongs, and quietly accepting it would allow-list something they did
// not read as an origin.
func canonicalize(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("not a valid URL: %w", err)
	}
	switch {
	case u.Scheme == "":
		return "", errors.New("missing scheme (want e.g. https://example.com)")
	case u.Host == "":
		return "", errors.New("missing host (want e.g. https://example.com)")
	case u.User != nil:
		return "", errors.New("must not contain userinfo")
	case u.Path != "" && u.Path != "/":
		return "", errors.New("must not contain a path")
	case u.RawQuery != "":
		return "", errors.New("must not contain a query string")
	case u.Fragment != "":
		return "", errors.New("must not contain a fragment")
	case strings.Contains(u.Host, "*"):
		// Matching is exact, so a wildcard entry would parse cleanly and then
		// match nothing — the operator believes a subdomain is allow-listed
		// while every request from it is rejected. Failing closed is the safe
		// direction, but silently is the wrong way to do it. List each origin
		// explicitly. (Wildcard matching is not offered on purpose: it is the
		// classic way origin checks fail open.)
		return "", errors.New("wildcards are not supported; list each origin explicitly")
	}
	// Scheme and host are case-insensitive; the port is not part of either and
	// is compared verbatim, so https://example.com and https://example.com:443
	// are distinct entries. That is correct per RFC 6454 — an origin is the
	// triple (scheme, host, port) — and browsers omit the default port, so
	// allow-list the form the client actually sends.
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

// Middleware rejects requests whose Origin header is present and not in
// allowed. It returns next unchanged when allowed is empty, so a deployment
// that has not opted in pays nothing per request.
//
// A request with NO Origin header is allowed through. That is the spec's own
// carve-out — "if the Origin header is present and invalid" — and it is what
// keeps every non-browser client working, which is nearly all MCP traffic.
//
// exemptPaths are matched exactly and skipped. /healthz belongs there: making
// the liveness signal depend on an origin allow-list means a misconfiguration
// takes the container down via the health check rather than surfacing as a
// visible 403, and infrastructure probes (Docker, Traefik, Prometheus) are not
// browser traffic in the first place.
func Middleware(allowed []string, exemptPaths ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(allowed) == 0 {
			return next
		}
		exempt := make(map[string]struct{}, len(exemptPaths))
		for _, p := range exemptPaths {
			exempt[p] = struct{}{}
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			o := r.Header.Get("Origin")
			if o == "" {
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := exempt[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}
			if isAllowed(o, allowed) {
				next.ServeHTTP(w, r)
				return
			}

			metrics.OriginRejectedTotal.Inc()
			// The rejected origin is attacker-controlled, so it is truncated
			// and never used as a metric label. Logged because an operator who
			// has just enabled this needs to see what they locked out.
			slog.Warn("origin rejected",
				"origin", truncate(o, maxLoggedOriginBytes),
				"path", r.URL.Path,
				"client_ip", realip.FromContext(r),
			)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "forbidden",
				"error_description": "Origin not allowed",
			})
		})
	}
}

// isAllowed reports whether the Origin header value matches an allow-list
// entry.
//
// Exact equality after canonicalization, never prefix or suffix matching.
// Suffix matching is the classic way origin checks fail open:
// "https://claude.ai.evil.com" ends with nothing useful, but a naive
// strings.HasPrefix(o, "https://claude.ai") accepts it outright.
//
// A value that does not canonicalize — "null", garbage, a bare hostname —
// matches nothing and is rejected. Parse has already refused "null" in the
// allow-list, so there is no entry for it to match even before this.
func isAllowed(o string, allowed []string) bool {
	canonical, err := canonicalize(o)
	if err != nil {
		return false
	}
	return slices.Contains(allowed, canonical)
}

// maxLoggedOriginBytes bounds the logged origin, which is attacker-controlled.
const maxLoggedOriginBytes = 256

// truncate cuts s at a safe UTF-8 boundary. Mirrors metrics.truncate; kept
// local rather than exported from metrics because a logging helper is not
// worth a cross-package dependency in that direction.
func truncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…(truncated)"
}
