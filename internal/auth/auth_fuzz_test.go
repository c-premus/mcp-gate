package auth

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzSanitizeQuotedString exercises the RFC 7235 quoted-string sanitizer with
// adversarial header values. The function is the last line of defense against
// header-splitting if a caller ever passes untrusted input into the
// WWW-Authenticate realm/error_description/resource_metadata slots.
//
// Invariants enforced for every input:
//
//   - Never panics.
//   - Output never contains CR, LF, NUL, or any C0 control byte except 0x09 (tab).
//   - Output never contains 0x7f (DEL).
//   - Output is valid UTF-8 (the function is byte-oriented but the input is
//     constrained to UTF-8 in production; fuzz inputs may not be, in which case
//     the surviving bytes still must compose valid UTF-8 because the sanitizer
//     either keeps a byte verbatim, drops it, or emits ASCII escapes).
//     We assert valid UTF-8 only when the input itself was valid UTF-8.
//   - Output length is bounded by 2*len(input): each input byte expands to at
//     most two output bytes (\\ or \").
//   - Every backslash in the output is part of a \\ or \" escape sequence —
//     never a dangling backslash that would corrupt the surrounding header.
func FuzzSanitizeQuotedString(f *testing.F) {
	seeds := []string{
		"",
		"grafana-mcp",
		`a"b`,
		`a\b`,
		`a\"b`,
		"a\nb",
		"a\rb",
		"a\r\nb",
		"a\x00b",
		"a\x7fb",
		"a\vb",
		"a\tb",
		"realm\r\nX-Evil: 1",
		"Gräfana-MCP",                                 // multi-byte UTF-8
		"\xc3\x28",                                    // invalid UTF-8 (continuation after non-leading)
		"\xff\xfe\xfd",                                // high-bit bytes
		"\x01\x02\x03\x04\x05\x06\x07\x08",            // C0 controls
		"\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14",        // more C0 controls
		"\"\"\\\\",                                    // quotes and backslashes
		strings.Repeat("\"", 64),                      // long quote run
		strings.Repeat("\\", 64),                      // long backslash run
		"https://example.com/\"path\"",                // URL with quotes
		"\xed\xa0\x80",                                // surrogate (invalid UTF-8)
		"\xf4\x90\x80\x80",                            // out-of-range UTF-8
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got := sanitizeQuotedString(in)

		// Length bound: each byte expands to at most two output bytes.
		if maxLen := 2 * len(in); len(got) > maxLen {
			t.Fatalf("output longer than 2x input: len(in)=%d len(got)=%d", len(in), len(got))
		}

		// No forbidden bytes ever leak into the output.
		for i := 0; i < len(got); i++ {
			c := got[i]
			switch {
			case c == '\t':
				// tab is explicitly preserved
			case c < 0x20:
				t.Fatalf("output byte at %d is C0 control 0x%02x; in=%q got=%q", i, c, in, got)
			case c == 0x7f:
				t.Fatalf("output byte at %d is DEL; in=%q got=%q", i, in, got)
			}
		}

		// Every backslash must be part of a valid escape sequence (\\ or \").
		// Walk the output and ensure no dangling backslash that would corrupt
		// the surrounding quoted-string.
		for i := 0; i < len(got); i++ {
			if got[i] != '\\' {
				continue
			}
			if i+1 >= len(got) {
				t.Fatalf("dangling backslash at end of output; in=%q got=%q", in, got)
			}
			next := got[i+1]
			if next != '\\' && next != '"' {
				t.Fatalf("backslash followed by 0x%02x (not \\ or \"); in=%q got=%q", next, in, got)
			}
			i++ // consume the escaped byte
		}

		// Bare double-quote in output would close the quoted-string. Any "
		// in the output must therefore be preceded by an escaping backslash
		// — which the loop above already verified are part of \" pairs. So
		// scanning for unescaped " here is the dual check.
		for i := 0; i < len(got); i++ {
			if got[i] == '"' && (i == 0 || got[i-1] != '\\') {
				t.Fatalf("unescaped quote at byte %d; in=%q got=%q", i, in, got)
			}
		}

		// UTF-8 validity round-trip: if the input was valid UTF-8, the output
		// must remain valid UTF-8. Multi-byte runes are preserved verbatim by
		// the byte-oriented sanitizer, so this catches any future regression
		// that interferes with continuation bytes.
		if utf8.ValidString(in) && !utf8.ValidString(got) {
			t.Fatalf("valid-UTF-8 input produced invalid-UTF-8 output; in=%q got=%q", in, got)
		}
	})
}
