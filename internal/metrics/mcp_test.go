package metrics

import (
	"slices"
	"strings"
	"testing"
)

// validMCPMethodLabels is the closed set mcpMethodLabel may emit. Keeping it
// tight is what bounds the mcp_method Prometheus label; any new branch must
// update this list, which is the point of the fuzz below.
var validMCPMethodLabels = []string{
	"server/discover",
	"tools/list",
	"tools/call",
	"resources/list",
	"resources/templates/list",
	"resources/read",
	"prompts/list",
	"prompts/get",
	"completion/complete",
	"subscriptions/listen",
	"notifications/cancelled",
	"other",
	"absent",
}

// validProtocolVersionLabels is the closed set mcpProtocolVersionLabel may emit.
var validProtocolVersionLabels = []string{
	"2026-07-28",
	"2025-11-25",
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
	"other",
	"absent",
}

func TestMCPMethodLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"tools/call passes through", "tools/call", "tools/call"},
		{"server/discover is new in 2026-07-28", "server/discover", "server/discover"},
		{"subscriptions/listen is new in 2026-07-28", "subscriptions/listen", "subscriptions/listen"},
		{"nested list method", "resources/templates/list", "resources/templates/list"},
		{"empty header", "", "absent"},

		// Removed in 2026-07-28. The Mcp-Method header did not exist when
		// these did, so in practice they arrive as "absent", not "other" —
		// but if a transitional client sends one anyway it must still be
		// clamped rather than creating a series.
		{"initialize was removed", "initialize", "other"},
		{"ping was removed", "ping", "other"},
		{"logging/setLevel was removed", "logging/setLevel", "other"},
		{"resources/subscribe was removed", "resources/subscribe", "other"},

		// Server-to-client methods can never appear inbound: under MRTR they
		// are embedded in results, not sent as requests.
		{"sampling is server-to-client", "sampling/createMessage", "other"},
		{"roots/list is server-to-client", "roots/list", "other"},

		// Extension methods, not core.
		{"tasks extension", "tasks/get", "other"},

		// Case-sensitive: header values are, per RFC 9110.
		{"wrong case is not the same method", "Tools/Call", "other"},

		{"garbage", "../../etc/passwd", "other"},
		{"very long value", strings.Repeat("a", 10_000), "other"},
		{"whitespace only", "   ", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mcpMethodLabel(tt.input)
			if got != tt.want {
				t.Errorf("mcpMethodLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if !slices.Contains(validMCPMethodLabels, got) {
				t.Errorf("mcpMethodLabel(%q) = %q, outside the bounded label set", tt.input, got)
			}
		})
	}
}

func TestMCPProtocolVersionLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"current revision", "2026-07-28", "2026-07-28"},
		{"previous revision", "2025-11-25", "2025-11-25"},
		{"oldest known revision", "2024-11-05", "2024-11-05"},
		{"absent", "", "absent"},
		{"a future revision we do not know yet", "2027-01-01", "other"},
		{"not a date", "latest", "other"},
		{"very long value", strings.Repeat("9", 10_000), "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mcpProtocolVersionLabel(tt.input)
			if got != tt.want {
				t.Errorf("mcpProtocolVersionLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if !slices.Contains(validProtocolVersionLabels, got) {
				t.Errorf("mcpProtocolVersionLabel(%q) = %q, outside the bounded label set", tt.input, got)
			}
		})
	}
}

func TestIsBase64Sentinel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"encoded value", "=?base64?SGVsbG8sIOS4lueVjA==?=", true},
		{"encoded empty payload", "=?base64??=", true},
		{"plain ascii", "list_datasources", false},
		{"resource uri", "file:///projects/myapp/config.json", false},
		{"empty", "", false},
		{"prefix without suffix", "=?base64?SGVsbG8", false},
		{"suffix without prefix", "SGVsbG8?=", false},
		// The markers are case-sensitive and must appear exactly as specified.
		{"wrong case prefix", "=?BASE64?SGVsbG8=?=", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isBase64Sentinel(tt.input); got != tt.want {
				t.Errorf("isBase64Sentinel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// FuzzMCPMethodLabel exercises the bounded-label clamp with arbitrary header
// values. Mcp-Method is client-controlled and unauthenticated at the point the
// metric is recorded, so this clamp is the only thing standing between a
// method-scanning client and unbounded Prometheus series.
//
// Invariants:
//
//   - Never panics.
//   - Output is always one of validMCPMethodLabels.
func FuzzMCPMethodLabel(f *testing.F) {
	seeds := []string{
		"tools/call",
		"server/discover",
		"resources/templates/list",
		"notifications/cancelled",
		"initialize",
		"",
		"   ",
		"tools/call ",  // trailing space — not the same method
		"TOOLS/CALL",   // case
		"tools//call",  // doubled separator
		"tools/call\n", // newline
		"\x00",
		strings.Repeat("a/", 4096), // very long, many separators
		"=?base64?dG9vbHMvY2FsbA==?=",
		"\xff\xfe", // invalid UTF-8
		"Grä",      // unicode
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, m string) {
		got := mcpMethodLabel(m)
		if !slices.Contains(validMCPMethodLabels, got) {
			t.Errorf("mcpMethodLabel(%q) = %q, outside the bounded label set %v",
				m, got, validMCPMethodLabels)
		}
	})
}

// FuzzMCPProtocolVersionLabel is the same contract for the protocol_version
// label, which is equally client-controlled.
func FuzzMCPProtocolVersionLabel(f *testing.F) {
	seeds := []string{
		"2026-07-28",
		"2025-11-25",
		"",
		"2026-07-28 ",
		"2026-7-28",
		"9999-99-99",
		strings.Repeat("2026-07-28,", 1000),
		"\x00",
		"\xff\xfe",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, v string) {
		got := mcpProtocolVersionLabel(v)
		if !slices.Contains(validProtocolVersionLabels, got) {
			t.Errorf("mcpProtocolVersionLabel(%q) = %q, outside the bounded label set %v",
				v, got, validProtocolVersionLabels)
		}
	})
}
