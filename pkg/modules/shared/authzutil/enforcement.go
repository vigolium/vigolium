package authzutil

import "strings"

// enforcementBodyLimit caps the number of bytes inspected in a response body for enforcement strings.
const enforcementBodyLimit = 4096

// authPageBodyLimit caps the bytes inspected for auth-challenge markers. Login
// shells render their form near the top of the document, so a generous prefix
// is enough without scanning megabyte-sized SPA bundles.
const authPageBodyLimit = 16384

// authChallengeMarkers are lowercase substrings that structurally identify an
// authentication or single-sign-on page — a login form, an OAuth/OIDC/SAML
// challenge, or an SSO consent screen — as opposed to a distinct application
// resource. They are deliberately structural (a password input, a known
// login-form action) rather than incidental words like "sign in" that can
// appear in the navigation of an already-authenticated page, so the detector
// stays low-false-positive.
var authChallengeMarkers = []string{
	`type="password"`,
	`type='password'`,
	`type=password`,
	`name="password"`,
	`name="passwd"`,
	`autocomplete="current-password"`,
	`autocomplete="new-password"`,
	`j_security_check`,
	`login-actions/authenticate`,
	`/openid-connect/auth`,
	`/oauth/authorize`,
	`/oauth2/authorize`,
	`/saml2/sso`,
	`id="kc-login"`,
}

// EnforcementStrings are substrings in response bodies that indicate authorization enforcement.
var EnforcementStrings = []string{
	"unauthorized",
	"forbidden",
	"access denied",
	"access_denied",
	"not authorized",
	"not_authorized",
	"permission denied",
	"permission_denied",
	"insufficient privileges",
	"insufficient permissions",
	"requires authentication",
	"authentication required",
	"login required",
	"you do not have permission",
	"you don't have permission",
	"not allowed",
	"no access",
	"invalid token",
	"token expired",
}

// LoginRedirectPatterns are URL path prefixes that indicate a login redirect.
var LoginRedirectPatterns = []string{
	"/login",
	"/signin",
	"/sign-in",
	"/auth/login",
	"/auth/signin",
	"/sso/",
	"/oauth/",
	"/cas/login",
}

// ContainsEnforcementString checks if the first 4KB of a response body contains any
// soft-denial substring indicating authorization enforcement.
func ContainsEnforcementString(body string) bool {
	limit := min(len(body), enforcementBodyLimit)
	lower := strings.ToLower(body[:limit])

	for _, s := range EnforcementStrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// IsAuthChallengePage reports whether a response body is an authentication or
// single-sign-on page (a login form, an OAuth/OIDC/SAML challenge, or an
// authorization-denied notice) rather than a distinct application object.
//
// IDOR/BOLA modules use this as a negative confirmation gate: a predicted
// identifier that merely returns the login page is not evidence of a
// predictable object reference. Every unauthenticated request to a protected
// endpoint returns the same login shell — only the per-request CSRF/session
// tokens differ — so a naive "200 + body differs from baseline" oracle fires on
// pure session-token noise (the Keycloak /openid-connect/auth false positive).
func IsAuthChallengePage(body string) bool {
	if body == "" {
		return false
	}
	limit := min(len(body), authPageBodyLimit)
	lower := strings.ToLower(body[:limit])

	for _, m := range authChallengeMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	// An access-denied / authentication-required notice is likewise not a
	// distinct resource the predicted identifier unlocked.
	return ContainsEnforcementString(body)
}

// IsLoginRedirect checks if a response is a redirect to a login page.
func IsLoginRedirect(statusCode int, location string) bool {
	if statusCode < 300 || statusCode >= 400 {
		return false
	}
	if location == "" {
		return false
	}
	lower := strings.ToLower(location)
	for _, pattern := range LoginRedirectPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
