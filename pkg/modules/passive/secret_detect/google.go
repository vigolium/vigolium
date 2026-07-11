package secret_detect

import "strings"

// IsReCaptchaSiteKey reports whether a secret-scan rule name identifies a Google
// reCAPTCHA key.
//
// reCAPTCHA *site* keys are public by design: they are embedded in page HTML/JS
// so the browser widget can render, and Google's model expects them to be
// visible. Only the paired server-side *secret* key (which verifies tokens) is
// sensitive. the reCAPTCHA rule cannot tell the two apart — both use the
// same `6L…` format — but a reCAPTCHA value served in an HTTP response body is
// overwhelmingly the public site key, so the finding is downgraded to
// informational rather than reported as a leaked credential.
func IsReCaptchaSiteKey(ruleName string) bool {
	return strings.Contains(strings.ToLower(ruleName), "recaptcha")
}

// IsGoogleAPIKey reports whether the match is a Google `AIza…` API key (Maps
// Platform, Gemini, Firebase, or a generic Google Cloud key — the shared prefix
// means the rule cannot always tell them apart, e.g. a Maps key is often
// labelled "Google Gemini API Key").
//
// The `AIza` snippet prefix uniquely marks this family regardless of the rule
// label, so it is the primary signal; the rule name is a fallback. These keys
// are frequently embedded in client-side code by design, so leakage is not
// account takeover — the real risk is billing/quota abuse against whichever
// Google APIs the key is enabled for and left unrestricted — and they are
// downgraded to Medium. A key flagged as validated still escalates to
// Critical ahead of this.
func IsGoogleAPIKey(ruleName, snippet string) bool {
	if strings.HasPrefix(strings.TrimSpace(snippet), "AIza") {
		return true
	}
	name := strings.ToLower(ruleName)
	return strings.Contains(name, "google") && strings.Contains(name, "api key")
}

// IsGoogleOAuthClientID reports whether the matched snippet is a Google OAuth
// client ID — the `NNNN-xxxx.apps.googleusercontent.com` identifier that
// Kingfisher's "Google OAuth Credentials" rule (kingfisher.google.6) matches.
//
// A client ID is the PUBLIC half of an OAuth client: it is embedded in every
// Google sign-in button and OAuth redirect by design, so its presence in a
// response is expected, not a leaked credential. The sensitive half is the
// paired client *secret* — a separate rule ("Google OAuth Client Secret"), and a
// separate finding — which keeps full severity. The `.apps.googleusercontent.com`
// suffix uniquely marks the client ID regardless of the rule label, so a match on
// it is reported as informational rather than a leaked secret.
func IsGoogleOAuthClientID(snippet string) bool {
	return strings.HasSuffix(strings.TrimSpace(snippet), ".apps.googleusercontent.com")
}

// secretFindingDescription returns the finding description for a secret match.
// Most secrets get the generic "Leaked secret detected: <rule>" line; the Google
// API key, reCAPTCHA site key, and OAuth client ID families carry richer
// descriptions that explain the actual (context-dependent) impact, matching the
// downgraded severities those rules now receive. Every description ends with the
// matched value so the leaked credential is visible in the finding body itself,
// not only in the separate ExtractedResults list, and then the detection pattern
// (the rule's RE2 regex that fired) so a reviewer can see exactly what was matched.
func secretFindingDescription(ruleName, snippet, pattern string) string {
	var base string
	switch {
	case IsReCaptchaSiteKey(ruleName):
		base = recaptchaSiteKeyDescription
	case IsGoogleOAuthClientID(snippet):
		base = googleOAuthClientIDDescription
	case IsGoogleAPIKey(ruleName, snippet):
		base = googleAPIKeyDescription
	default:
		base = "Leaked secret detected: " + ruleName
	}
	return appendDetectionPattern(appendMatchedValue(base, snippet), pattern)
}

// appendDetectionPattern appends the rule's RE2 regex to a finding description as
// a trailing "Detection pattern:" line, so the finding shows exactly what was
// grepped for. A blank pattern is left off; the full pattern is kept (no cap).
func appendDetectionPattern(desc, pattern string) string {
	return appendLabeledCode(desc, "Detection pattern", pattern, 0)
}

// matchedValueMaxLen caps how much of the matched secret is inlined into the
// finding description. A long connection string or JWT is truncated with an
// ellipsis so the description stays readable; the full value remains in
// ExtractedResults and the windowed response evidence.
const matchedValueMaxLen = 200

// appendMatchedValue appends the matched secret to a finding description as a
// trailing "Matched value:" line. A blank snippet is left off entirely.
func appendMatchedValue(desc, snippet string) string {
	return appendLabeledCode(desc, "Matched value", snippet, matchedValueMaxLen)
}

// appendLabeledCode appends a "**<label>:** `<value>`" paragraph to desc, fenced
// in inline code. The value is trimmed, any embedded newline is collapsed to a
// space so it stays on one line, and — when maxLen > 0 — it is truncated with an
// ellipsis. A blank value adds nothing. Shared by appendMatchedValue and
// appendDetectionPattern so their trim/collapse/fence formatting can't drift.
func appendLabeledCode(desc, label, value string, maxLen int) string {
	shown := strings.TrimSpace(value)
	if shown == "" {
		return desc
	}
	shown = strings.ReplaceAll(shown, "\n", " ")
	shown = strings.ReplaceAll(shown, "\r", " ")
	if maxLen > 0 && len(shown) > maxLen {
		shown = shown[:maxLen] + "…"
	}
	return desc + "\n\n**" + label + ":** `" + shown + "`"
}

const googleAPIKeyDescription = `**What it means:** A Google API key (the AIza… family — Maps Platform, Gemini, Firebase, or a generic Google Cloud key) is served in this response. These keys are routinely embedded in client-side code by design, so exposure alone is not account takeover.

**How it's exploited:** The risk is billing and quota abuse. If the key carries no application restriction (HTTP referrer, IP, Android, or iOS) and is enabled for billable APIs — Maps Platform (Geocoding, Directions, Places, Static Maps, Distance Matrix) or Gemini/Cloud APIs — an attacker calls those endpoints at scale to run up the owner's bill or exhaust quota, a financial denial of service. HTTP referrer restrictions are weak: the Referer header is attacker-controlled and trivially spoofed, so a web-restricted key is often still abusable server-side.

**Fix:** Restrict the key to the specific APIs and applications it needs, and rotate it if it is unrestricted. Confirm exposure by probing one billable endpoint (e.g. Static Maps or Geocoding) — a valid response instead of REQUEST_DENIED proves the key is callable.`

const googleOAuthClientIDDescription = `**What it means:** This is a Google OAuth client ID (the NNNN-xxxx.apps.googleusercontent.com identifier) — the public half of an OAuth client. Client IDs are embedded in every Google sign-in button and OAuth redirect flow by design, so their presence in a response is expected, not a leaked credential. The sensitive half is the paired client secret, which is reported separately when present.

**How it's exploited:** Nothing on its own. A client ID cannot authenticate or authorize a caller; it only identifies the OAuth application. It becomes useful to an attacker only when paired with a leaked client secret, refresh token, or access token (each its own finding) — check this same response for those, as a leaked client ID often sits beside them.

**Fix:** No action is required for the client ID itself. Ensure the paired client secret, refresh tokens, and access tokens are never served in client-facing content; if any of them appear alongside this client ID, rotate them immediately.`

const recaptchaSiteKeyDescription = `**What it means:** This is a Google reCAPTCHA site key. Site keys are public by design — they are embedded in page HTML/JS so the browser widget can render, and Google's model expects them to be visible. The server-side secret key that verifies tokens is the only sensitive half of the pair and is not present here.

**How it's exploited:** Nothing directly. A site key cannot bypass reCAPTCHA, forge verifications, or impersonate the site; it is reported for awareness only.

**Fix:** No action is required for the site key itself. Ensure the paired secret key is never exposed in client-facing content.`
