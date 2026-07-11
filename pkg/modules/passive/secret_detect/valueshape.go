package secret_detect

import "strings"

// IsValueShapeNoise reports whether a matched secret VALUE is a structural false
// positive by its shape alone. The first two shapes are caught regardless of
// which rule matched; the third is scoped to the generic-credential rule family:
//
//   - A Google reCAPTCHA site key (6L… 40 chars) matched by a rule that is NOT
//     the reCAPTCHA rule — the public widget key mis-attributed as some other
//     provider's secret (e.g. a generic rule firing on a `data-sitekey` value).
//     A correctly-attributed reCAPTCHA match is handled by the severity layer
//     (Info), not dropped here.
//   - A code/markup fragment rather than a credential token — the captured value
//     carries a character that never appears inside a real credential
//     (whitespace, an HTML angle bracket, a JS/JSON brace, a quote, a backtick,
//     or a parenthesis). This is the dominant shape of the low-confidence
//     generic-rule captures, e.g. `":"1234"}</li>` from a "Generic Username and
//     Password" match on page markup.
//   - A source-code / UI identifier slug captured by a generic username/password
//     rule — a word-only identifier like `label-password` or `passwordConfirm`
//     grabbed from a compiled JS bundle's component metadata (see
//     isIdentifierSlug). Scoped to that rule family so it never second-guesses a
//     provider-specific rule's capture.
//
// Callers apply this ONLY to untrusted-tier matches (medium/low-confidence
// rules): the curated high-confidence rules are anchored tightly enough that
// their captures are trusted verbatim and never second-guessed by value shape.
//
// A plain hex digest is deliberately NOT treated as noise: real provider secrets
// (Mailgun, Weights & Biases, …) are fixed-width hex, and the webpack
// content-hash-manifest case is already dropped by IsChunkHashManifestMatch.
func IsValueShapeNoise(ruleName, secret string) bool {
	s := strings.TrimSpace(secret)
	if s == "" {
		return false
	}
	if !IsReCaptchaSiteKey(ruleName) && isReCaptchaSiteKeyShape(s) {
		return true
	}
	if hasNonCredentialChar(s) {
		return true
	}
	// The generic username/password proximity rules capture whatever token sits
	// near a user/password keyword. Inside a compiled JS bundle that is routinely
	// a source/UI identifier — a Stencil `label-password` attribute name or a
	// `passwordConfirm` prop — rather than a credential. Drop those word-only
	// identifier slugs, but only for that generic-credential family: other rules
	// keep their captures verbatim.
	if isGenericCredentialRule(ruleName) && isIdentifierSlug(s) {
		return true
	}
	return false
}

// isGenericCredentialRule reports whether ruleName is one of the low-confidence
// kingfisher proximity heuristics that grab the token adjacent to a
// user/password keyword ("Generic Username and Password" — kingfisher.generic.3
// / .4 — and "Generic Password" — .5). These are the rules prone to capturing a
// neighbouring code/markup identifier, so the identifier-slug guard applies to
// them alone.
func isGenericCredentialRule(ruleName string) bool {
	switch ruleName {
	case "Generic Username and Password", "Generic Password":
		return true
	}
	return false
}

// isIdentifierSlug reports whether s is a source-code / UI identifier — word
// segments joined by `-`, `_`, or a camelCase boundary, carrying no digits or
// other entropy — rather than a credential value. These are the dominant capture
// of the generic username/password proximity rules when they fire inside a
// minified web-component bundle, e.g. `label-password`, `label-unmatched-passwords`,
// and `passwordConfirm`.
//
// Requiring BOTH a word boundary (a `-`/`_` separator or a lower→upper camelCase
// transition) AND a pure-letter body is what keeps real low-entropy passwords in
// scope: any digit or symbol (`hunter2`, `P@ssw0rd`, an opaque token) fails the
// letter-only check, and a single unbroken word (`admin`, `correcthorsebattery`)
// has no boundary — so all of those are left untouched. The residual give-up is a
// letters-only multi-word password like `SuperSecretPass`; as a literal sitting
// beside a user/password keyword that is far more likely a variable or label than
// a live credential, and the finding is only the untrusted Suspect tier anyway.
func isIdentifierSlug(s string) bool {
	sawSeparator := false     // an explicit '-' or '_' word separator
	sawCamelBoundary := false // a lower→upper transition (camelCase / PascalCase)
	var prev byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' || c == '_':
			sawSeparator = true
		case c >= 'a' && c <= 'z':
			// lowercase letter — part of a word segment
		case c >= 'A' && c <= 'Z':
			if i > 0 && prev >= 'a' && prev <= 'z' {
				sawCamelBoundary = true
			}
		default:
			// a digit or any other character means this carries entropy /
			// structure a plain word identifier never has — not a slug.
			return false
		}
		prev = c
	}
	return sawSeparator || sawCamelBoundary
}

// isReCaptchaSiteKeyShape reports whether s has the Google reCAPTCHA site-key
// shape: the literal prefix "6L" followed by 38 URL-safe-base64 characters
// (40 total). Both reCAPTCHA v2 and v3 site keys use this format.
func isReCaptchaSiteKeyShape(s string) bool {
	if len(s) != 40 || s[0] != '6' || s[1] != 'L' {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// hasNonCredentialChar reports whether s contains a character that never appears
// inside a real credential token. The credential formats in scope — API keys,
// base64/JWT tokens, connection strings, URIs — use only [A-Za-z0-9] plus a
// small punctuation set (_ - . / + = : @ ~ % # & ? and base64 padding), so any
// whitespace or markup/code structural character below signals a code/markup
// capture rather than a secret. The set is intentionally conservative: `;`, `=`,
// `,`, and `:` are excluded because connection strings and base64 padding use
// them, so they are not reliable non-credential signals.
func hasNonCredentialChar(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '<', '>', '{', '}', '"', '\'', '`', '(', ')':
			return true
		}
	}
	return false
}
