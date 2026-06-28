package secret_detect

import "bytes"

// IsJSEscapeArtifactMatch reports whether the matched snippet is a JavaScript
// source identifier that a fixed-length / high-entropy token rule clipped out of
// a `\uXXXX` (or `\xXX`) escape sequence, rather than a real delimited
// credential.
//
// Minified framework bundles export private symbols under a non-ASCII prefix
// emitted as a unicode escape — Angular's "ɵ" prefix is written as the literal
// six-character escape backslash-u-0-2-7-5, so a bundle is full of
// (ɵ)setUnknownElementStrictMode, (ɵ)makeDecorator, and the like. A
// generic [A-Za-z0-9]{32}-style rule
// (ZeroTier's API token, etc.) cannot include the leading backslash, so it
// matches starting at the escape's hex body, yielding a 32-char snippet such as
// "u0275setUnknownElementStrictMode". The escape is unambiguous proof the value
// is source code: a credential is never written as a literal \uXXXX run.
//
// The check is structural and conservative — like IsBinaryBlobMatch it only
// fires when the snippet can be positively located glued to a `\u`/`\x` escape
// in the body, so a genuine secret served in the same bundle is still reported,
// and a snippet that cannot be found verbatim keeps the finding.
func IsJSEscapeArtifactMatch(body []byte, snippet string) bool {
	if snippet == "" || len(body) == 0 {
		return false
	}
	idx := bytes.Index(body, []byte(snippet))
	if idx <= 0 {
		return false
	}
	// Case A: the rule swallowed the escape's hex tail — the snippet itself
	// begins with the `uXXXX` / `xXX` body of an escape whose backslash sits
	// immediately before the match (`\` + `u0275setUnknown…`).
	if body[idx-1] == '\\' && startsWithEscapeBody(snippet) {
		return true
	}
	// Case B: the rule matched a clean identifier sitting immediately after a
	// complete `\uXXXX` (6 bytes) or `\xXX` (4 bytes) escape (`ɵ` followed
	// by a 32-char identifier).
	if endsWithEscape(body[:idx]) {
		return true
	}
	return false
}

// startsWithEscapeBody reports whether s begins with the body of a JS escape:
// `u` + 4 hex digits (`\uXXXX`) or `x` + 2 hex digits (`\xXX`), minus the
// leading backslash the credential rule could not match.
func startsWithEscapeBody(s string) bool {
	if len(s) >= 5 && (s[0] == 'u' || s[0] == 'U') && isHexRun(s[1:5]) {
		return true
	}
	return len(s) >= 3 && (s[0] == 'x' || s[0] == 'X') && isHexRun(s[1:3])
}

// endsWithEscape reports whether prefix ends with a complete `\uXXXX` or `\xXX`
// escape sequence.
func endsWithEscape(prefix []byte) bool {
	n := len(prefix)
	if n >= 6 && prefix[n-6] == '\\' && (prefix[n-5] == 'u' || prefix[n-5] == 'U') && isHexRun(string(prefix[n-4:n])) {
		return true
	}
	return n >= 4 && prefix[n-4] == '\\' && (prefix[n-3] == 'x' || prefix[n-3] == 'X') && isHexRun(string(prefix[n-2:n]))
}

// isHexRun reports whether every byte of s is an ASCII hex digit (and s is
// non-empty).
func isHexRun(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
