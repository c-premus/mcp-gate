package auth

import "testing"

func TestSanitizeQuotedString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no special chars", "grafana-mcp", "grafana-mcp"},
		{"backslash escaped", `a\b`, `a\\b`},
		{"quote escaped", `a"b`, `a\"b`},
		{"both escaped", `a\"b`, `a\\\"b`},
		{"injection attempt", `realm" , evil="payload`, `realm\" , evil=\"payload`},
		{"multiple quotes", `""`, `\"\"`},
		{"multiple backslashes", `\\`, `\\\\`},
		{"newline stripped", "a\nb", "ab"},
		{"carriage return stripped", "a\rb", "ab"},
		{"crlf stripped", "a\r\nb", "ab"},
		{"null byte stripped", "a\x00b", "ab"},
		{"del stripped", "a\x7fb", "ab"},
		{"vertical tab stripped", "a\vb", "ab"},
		{"header injection attempt", "realm\r\nX-Evil: 1", "realmX-Evil: 1"},
		{"tab preserved", "a\tb", "a\tb"},
		{"unicode preserved", "Gräfana-MCP", "Gräfana-MCP"},
		{"url with quotes", `https://example.com/"path"`, `https://example.com/\"path\"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeQuotedString(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeQuotedString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
