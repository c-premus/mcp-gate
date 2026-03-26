// Package metadata serves RFC 9728 Protected Resource Metadata.
package metadata

import (
	"encoding/json"
	"log"
	"net/http"
)

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
func Handler(meta ProtectedResourceMetadata) http.HandlerFunc {
	data, err := json.Marshal(meta)
	if err != nil {
		log.Fatalf("metadata: failed to marshal: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}
