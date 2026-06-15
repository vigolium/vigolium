// Package loginsig holds shared signatures for recognizing login/SSO walls
// from a URL or a response body alone, without loading a page in a browser.
//
// The crawler uses these to classify an off-host start-redirect landing; the
// targeted re-spider phase uses them as a cheap pre-flight screen so it never
// spends a browser on an authentication page. Keeping the tables here gives
// both callers one source of truth instead of duplicating the IdP list.
package loginsig

import (
	"bytes"
	"net/url"
	"strings"
)

// loginHostPrefixes are subdomain prefixes that conventionally front an
// authentication endpoint (e.g. login.example.com, sso.example.com).
var loginHostPrefixes = []string{
	"login.", "signin.", "sso.", "adfs.", "auth.", "accounts.", "idp.", "sts.",
}

// loginIDPHosts are registrable hosts of common identity providers and managed
// access gateways. Matched exactly or as a parent suffix (e.g. tenant.okta.com
// matches okta.com, acme.cloudflareaccess.com matches cloudflareaccess.com).
var loginIDPHosts = []string{
	"login.microsoftonline.com", "login.live.com", "login.windows.net",
	"accounts.google.com", "okta.com", "auth0.com", "onelogin.com",
	"pingidentity.com", "login.salesforce.com", "fs.gov",
	// Managed identity-aware proxies that front an app with their own auth
	// wall. The host is the gate, not the protected app, so any path on it is
	// an authentication page.
	"cloudflareaccess.com",
}

// loginPathMarkers are substrings of an authentication URL's path/query.
var loginPathMarkers = []string{
	"/oauth2/authorize", "/oauth/authorize", "/connect/authorize",
	"/adfs/", "/saml", "/signin", "/login", "/openid", "/sso",
	"response_type=code", "response_type=token",
	// Cloudflare Access portal endpoints (login / verify-code / callback).
	"/cdn-cgi/access/",
}

// LooksLikeLoginURL reports whether u points at an authentication endpoint,
// based on its host and path/query alone (no page load required).
func LooksLikeLoginURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, p := range loginHostPrefixes {
		if strings.HasPrefix(host, p) {
			return true
		}
	}
	for _, idp := range loginIDPHosts {
		if host == idp || strings.HasSuffix(host, "."+idp) {
			return true
		}
	}
	pathQ := strings.ToLower(u.Path + "?" + u.RawQuery)
	for _, m := range loginPathMarkers {
		if strings.Contains(pathQ, m) {
			return true
		}
	}
	return false
}

// passwordFieldMarkers are byte patterns that indicate a rendered login form
// — a visible password input. Matched case-insensitively against an HTML body.
var passwordFieldMarkers = [][]byte{
	[]byte(`type="password"`),
	[]byte(`type='password'`),
	[]byte(`type=password`),
}

// ssoWallMarkers identify managed / passwordless authentication walls that carry
// no password input but are still an auth gate rather than application content —
// notably Cloudflare Access, whose verify-code portal uses a one-time-code text
// field. Markers are Cloudflare-Access-specific shell class names that survive
// HTML-entity encoding of the page's URLs, so they match the rendered body even
// when every href/action is entity-escaped. Matched case-insensitively.
var ssoWallMarkers = [][]byte{
	[]byte(`class="authbox`),       // Cloudflare Access auth shell container
	[]byte(`class="authformlogin`), // Cloudflare Access login/verify-code form
}

// BodyLooksLikeLogin reports whether an HTML body is a login / SSO wall, the
// strongest no-browser signal short of loading the page. It fires on a password
// input (the common case) or on a recognized managed / passwordless auth shell
// such as Cloudflare Access. The body is lower-cased once for the match.
func BodyLooksLikeLogin(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body)
	for _, m := range passwordFieldMarkers {
		if bytes.Contains(lower, m) {
			return true
		}
	}
	for _, m := range ssoWallMarkers {
		if bytes.Contains(lower, m) {
			return true
		}
	}
	return false
}
