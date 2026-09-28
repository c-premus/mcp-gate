package auth

import "testing"

// TestScopesSatisfy pins the MCP 2026-07-28 scope-hierarchy MUST:
// "Servers MUST account for scope hierarchies, where a broader scope implies
// narrower ones, when deciding whether a token is sufficient for an operation."
//
// The implication is one-directional. Getting the direction backwards would be
// a privilege escalation, not a hierarchy, so the negative cases here matter
// more than the positive ones.
func TestScopesSatisfy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		granted  []string
		required string
		want     bool
	}{
		// Exact match — the pre-existing behaviour, unchanged.
		{"exact match", []string{"openid"}, "openid", true},
		{"exact match among several", []string{"profile", "openid", "email"}, "openid", true},
		{"absent", []string{"profile"}, "openid", false},
		{"empty granted", nil, "openid", false},

		// Broader implies narrower — the MUST.
		{"broad grants narrow", []string{"files"}, "files:read", true},
		{"broad grants deep narrow", []string{"files"}, "files:read:own", true},
		{"mid grants deeper", []string{"files:read"}, "files:read:own", true},

		// Narrow does NOT imply broad. This is the escalation direction.
		{"narrow does not grant broad", []string{"files:read"}, "files", false},
		{"narrow does not grant sibling", []string{"files:read"}, "files:write", false},
		{"deep does not grant mid", []string{"files:read:own"}, "files:read", false},

		// Segment boundaries. A prefix that does not end at the separator is
		// an unrelated scope that merely shares leading characters.
		{"prefix without separator is unrelated", []string{"file"}, "files:read", false},
		{"prefix without separator, exact-ish", []string{"admin"}, "administrator", false},
		{"separator must follow granted exactly", []string{"files:"}, "files:read", false},

		// Flat scopes (what Authentik issues) behave exactly as before.
		{"flat scopes unaffected", []string{"openid", "profile"}, "email", false},
		{"flat scope satisfied", []string{"openid", "profile"}, "profile", true},

		// Degenerate inputs must not panic or over-grant.
		{"empty required", []string{"files"}, "", false},
		{"empty granted entry", []string{""}, "files", false},
		{"empty granted entry, empty required", []string{""}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scopesSatisfy(tt.granted, tt.required); got != tt.want {
				t.Errorf("scopesSatisfy(%q, %q) = %v, want %v",
					tt.granted, tt.required, got, tt.want)
			}
		})
	}
}

// TestCutBearerPrefix pins RFC 9110 §11.1 (auth-scheme is case-insensitive)
// and §11.6.2 (more than one SP may separate scheme from credentials).
//
// The case-sensitive strings.CutPrefix this replaced told a client sending
// `bearer <valid token>` that it had supplied NO credentials — a 401 with no
// error parameter, which is both wrong and misleading to debug.
func TestCutBearerPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		header    string
		wantToken string
		wantOK    bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"BeArEr abc", "abc", true},

		// Extra whitespace between scheme and credentials is permitted.
		{"Bearer   abc", "abc", true},
		{"Bearer\tabc", "abc", true},

		// The token itself stays case-sensitive and is not otherwise touched.
		{"Bearer AbC.dEf", "AbC.dEf", true},

		// Not the Bearer scheme.
		{"Token abc", "", false},
		{"Basic dXNlcjpwYXNz", "", false},
		{"", "", false},

		// A scheme match must end at whitespace, or "Bearerfoo" would parse as
		// the Bearer scheme carrying "foo".
		{"Bearerfoo", "", false},
		{"Bearer", "", false},

		// Scheme present, credentials absent — matches the scheme but yields an
		// empty token, which the caller rejects as no_token.
		{"Bearer ", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			t.Parallel()
			gotToken, gotOK := cutBearerPrefix(tt.header)
			if gotToken != tt.wantToken || gotOK != tt.wantOK {
				t.Errorf("cutBearerPrefix(%q) = (%q, %v), want (%q, %v)",
					tt.header, gotToken, gotOK, tt.wantToken, tt.wantOK)
			}
		})
	}
}
