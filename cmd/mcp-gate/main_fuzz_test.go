package main

import (
	"strings"
	"testing"
)

// FuzzSplitCSV exercises the CSV splitter that backs REQUIRED_SCOPES,
// SCOPES_SUPPORTED, and TRUSTED_PROXIES env-var parsing. The function trims
// ASCII whitespace from each element, drops empties, and returns nil when
// nothing survives.
//
// Invariants for every input:
//
//   - Never panics.
//   - No element is the empty string.
//   - No element has leading or trailing ASCII whitespace.
//   - Total joined length (without commas) is <= len(input).
//   - When the result is non-empty, every element is a substring of the input.
func FuzzSplitCSV(f *testing.F) {
	seeds := []string{
		"",
		",",
		",,,",
		" , , ",
		"openid",
		"openid,profile",
		" openid , profile , email ",
		"openid,",
		",openid",
		"\t openid \t",
		"a\x00b,c",                       // embedded NUL
		"a，b",                            // multibyte fullwidth comma (U+FF0C) — should NOT split
		"openid,openid,openid",           // duplicates allowed by contract
		strings.Repeat(",", 256),          // long all-comma input
		strings.Repeat("a,", 256),         // many single-char entries
		"  \t\n\r  ",                      // pure whitespace including non-space
		"a\nb",                            // embedded newline (TrimSpace strips it as boundary)
		"172.20.0.0/16,10.0.0.0/8",       // realistic TRUSTED_PROXIES
		"\xff,\xfe",                       // non-UTF-8 bytes
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got := splitCSV(in)

		// Empty result must be nil per the function's contract — used by
		// callers as the "unset" signal for TRUSTED_PROXIES, etc.
		if len(got) == 0 {
			if got != nil {
				t.Fatalf("empty result must be nil, got non-nil zero-length slice; in=%q", in)
			}
			return
		}

		var totalLen int
		for i, p := range got {
			if p == "" {
				t.Fatalf("element %d is empty; in=%q got=%v", i, in, got)
			}
			if trimmed := strings.TrimSpace(p); trimmed != p {
				t.Fatalf("element %d %q has leading/trailing whitespace; in=%q",
					i, p, in)
			}
			// strings.TrimSpace strips Unicode whitespace, so a fully-trimmed
			// element should itself round-trip through TrimSpace unchanged.
			if !strings.Contains(in, p) {
				t.Fatalf("element %d %q is not a substring of input %q",
					i, p, in)
			}
			totalLen += len(p)
		}

		if totalLen > len(in) {
			t.Fatalf("joined element bytes (%d) exceed input length (%d); in=%q got=%v",
				totalLen, len(in), in, got)
		}
	})
}
