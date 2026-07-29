// Package metadata serves RFC 9728 Protected Resource Metadata.
//
// It provides an HTTP handler for the /.well-known/oauth-protected-resource
// endpoint, returning a static JSON document that directs MCP clients to the
// appropriate OAuth 2.1 authorization server.
package metadata

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownPath is the RFC 9728 well-known URI path for Protected Resource
// Metadata. It is the single source of truth for this string: the route
// registration, the metrics route classifier, and the resource_metadata
// parameter of every WWW-Authenticate challenge all derive from it.
const WellKnownPath = "/.well-known/oauth-protected-resource"

// URLFor returns the absolute URL of the Protected Resource Metadata document
// for resourceURI.
//
// Per RFC 9728 §3.1 the well-known segment is inserted between the authority
// and the resource's path, so a resource at https://example.com/mcp publishes
// its metadata at https://example.com/.well-known/oauth-protected-resource/mcp
// — not at https://example.com/mcp/.well-known/oauth-protected-resource. For a
// root-mounted resource (mcp-gate's own deployment) both readings collapse to
// the same URL.
//
// If resourceURI is not an absolute URL, URLFor falls back to appending the
// well-known path. RESOURCE_URI is validated at startup, so the fallback is
// unreachable in practice; it exists so the function is total.
func URLFor(resourceURI string) string {
	u, err := url.Parse(resourceURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimSuffix(resourceURI, "/") + WellKnownPath
	}
	return (&url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   WellKnownPath + PathSuffix(resourceURI),
	}).String()
}

// PathSuffix returns the path component of resourceURI with any trailing slash
// removed, or "" when the resource is mounted at the root. It is the segment
// RFC 9728 §3.1 appends after WellKnownPath, and it is also what decides
// whether a deployment needs a second, path-suffixed metadata route.
func PathSuffix(resourceURI string) string {
	u, err := url.Parse(resourceURI)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(u.Path, "/")
}

// ProtectedResourceMetadata represents the RFC 9728 Protected Resource Metadata response.
// Defined inline to avoid heavy transitive dependencies from go-sdk/oauthex.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// Handler returns an http.HandlerFunc that serves the given metadata as JSON.
// The JSON is pre-marshaled at construction time to avoid repeated encoding and
// to surface marshaling errors at startup rather than at request time.
func Handler(meta ProtectedResourceMetadata) (http.HandlerFunc, error) {
	data, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("metadata marshal: %w", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// max-age=300 keeps caches fresh in case AUTHORIZATION_SERVER is reconfigured;
		// must-revalidate forbids serving stale entries past the TTL.
		w.Header().Set("Cache-Control", "max-age=300, must-revalidate")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}, nil
}
