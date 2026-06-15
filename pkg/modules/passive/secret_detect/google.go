package secret_detect

import "strings"

// IsReCaptchaSiteKey reports whether a Kingfisher rule name identifies a Google
// reCAPTCHA key.
//
// reCAPTCHA *site* keys are public by design: they are embedded in page HTML/JS
// so the browser widget can render, and Google's model expects them to be
// visible. Only the paired server-side *secret* key (which verifies tokens) is
// sensitive. Kingfisher's reCAPTCHA rule cannot tell the two apart — both use the
// same `6L…` format — but a reCAPTCHA value served in an HTTP response body is
// overwhelmingly the public site key, so the finding is downgraded to
// informational rather than reported as a leaked credential.
func IsReCaptchaSiteKey(ruleName string) bool {
	return strings.Contains(strings.ToLower(ruleName), "recaptcha")
}

// IsGoogleAPIKey reports whether the match is a Google `AIza…` API key (Maps
// Platform, Gemini, Firebase, or a generic Google Cloud key — the shared prefix
// means Kingfisher cannot always tell them apart, e.g. a Maps key is often
// labelled "Google Gemini API Key").
//
// The `AIza` snippet prefix uniquely marks this family regardless of the rule
// label, so it is the primary signal; the rule name is a fallback. These keys
// are frequently embedded in client-side code by design, so leakage is not
// account takeover — the real risk is billing/quota abuse against whichever
// Google APIs the key is enabled for and left unrestricted — and they are
// downgraded to Medium. A key Kingfisher validates as live still escalates to
// Critical ahead of this.
func IsGoogleAPIKey(ruleName, snippet string) bool {
	if strings.HasPrefix(strings.TrimSpace(snippet), "AIza") {
		return true
	}
	name := strings.ToLower(ruleName)
	return strings.Contains(name, "google") && strings.Contains(name, "api key")
}

// secretFindingDescription returns the finding description for a secret match.
// Most secrets get the generic "Leaked secret detected: <rule>" line; the
// Google API key and reCAPTCHA site key families carry richer descriptions that
// explain the actual (context-dependent) impact, matching the downgraded
// severities those rules now receive.
func secretFindingDescription(ruleName, snippet string) string {
	switch {
	case IsReCaptchaSiteKey(ruleName):
		return recaptchaSiteKeyDescription
	case IsGoogleAPIKey(ruleName, snippet):
		return googleAPIKeyDescription
	default:
		return "Leaked secret detected: " + ruleName
	}
}

const googleAPIKeyDescription = `**What it means:** A Google API key (the AIza… family — Maps Platform, Gemini, Firebase, or a generic Google Cloud key) is served in this response. These keys are routinely embedded in client-side code by design, so exposure alone is not account takeover.

**How it's exploited:** The risk is billing and quota abuse. If the key carries no application restriction (HTTP referrer, IP, Android, or iOS) and is enabled for billable APIs — Maps Platform (Geocoding, Directions, Places, Static Maps, Distance Matrix) or Gemini/Cloud APIs — an attacker calls those endpoints at scale to run up the owner's bill or exhaust quota, a financial denial of service. HTTP referrer restrictions are weak: the Referer header is attacker-controlled and trivially spoofed, so a web-restricted key is often still abusable server-side.

**Fix:** Restrict the key to the specific APIs and applications it needs, and rotate it if it is unrestricted. Confirm exposure by probing one billable endpoint (e.g. Static Maps or Geocoding) — a valid response instead of REQUEST_DENIED proves the key is callable.`

const recaptchaSiteKeyDescription = `**What it means:** This is a Google reCAPTCHA site key. Site keys are public by design — they are embedded in page HTML/JS so the browser widget can render, and Google's model expects them to be visible. The server-side secret key that verifies tokens is the only sensitive half of the pair and is not present here.

**How it's exploited:** Nothing directly. A site key cannot bypass reCAPTCHA, forge verifications, or impersonate the site; it is reported for awareness only.

**Fix:** No action is required for the site key itself. Ensure the paired secret key is never exposed in client-facing content.`
