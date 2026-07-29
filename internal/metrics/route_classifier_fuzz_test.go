package metrics

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// validRouteLabels is the closed set of route labels the classifier may emit.
// Keeping this set tight is what bounds the route Prometheus label cardinality;
// any new branch must update this list (and is the whole point of the fuzz).
var validRouteLabels = []string{"metadata", "healthz", "proxy"}

// FuzzRouteClassifier exercises the bounded-label classifier with arbitrary
// request paths. The cardinality of the route label is the only thing keeping
// mcpgate_http_requests_total from exploding under attacker-controlled URLs.
//
// Invariants:
//
//   - Never panics.
//   - Output is always one of validRouteLabels.
func FuzzRouteClassifier(f *testing.F) {
	seeds := []string{
		"/",
		"/healthz",
		"/.well-known/oauth-protected-resource",
		"/foo/bar/baz",
		"/mcp",
		"/mcp/v1",
		"/mcp/../etc/passwd",
		"/healthz/",                              // trailing slash — should NOT match healthz
		"/HEALTHZ",                               // case sensitivity
		"/.well-known/oauth-protected-resource/", // trailing slash variant
		"/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-protected-resource/public/mcp",
		"/.well-known/oauth-protected-resourceXYZ", // near-miss, no separator
		"/.well-known/oauth-protected-resource/..%2f",
		"",
		"/" + strings.Repeat("a", 4096), // very long path
		"/\x00",                         // NUL byte
		"/foo%2fbar",                    // URL-encoded
		"/Grä",                          // unicode
		"/\xff\xfe",                     // invalid UTF-8
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		// Build the request directly with a hand-constructed URL so the URL
		// parser doesn't reject pathological fuzz inputs (control bytes,
		// invalid UTF-8) that net/http would otherwise filter on the wire.
		// RouteClassifier only reads r.URL.Path, so that field is all that
		// matters here.
		r := &http.Request{
			Method: http.MethodGet,
			URL:    &url.URL{Path: path},
		}

		got := RouteClassifier(r)
		if !slices.Contains(validRouteLabels, got) {
			t.Fatalf("RouteClassifier returned out-of-set label %q; path=%q valid=%v",
				got, path, validRouteLabels)
		}
	})
}
