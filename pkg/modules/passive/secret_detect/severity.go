package secret_detect

import (
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// SecretFindingSeverity computes the severity and confidence for a native
// secret-scan finding from its rule identity and where/how it was observed.
//
// Rule identity sets the baseline. A recognisable secret family grades High: the
// curated high-confidence kingfisher rules (trusted — the ~86 provider-specific
// patterns: Stripe / Checkout secret keys, Azure connection strings, CircleCI
// PATs, …) at Firm, and every other NAMED provider family (a medium/low-confidence
// rule like Storyblok / Bitfinex / Google Gemini) at Tentative — a named leak is
// surfaced for triage at full weight, its Tentative confidence flagging that it is
// unverified. Only the GENERIC, family-less matchers (generic — the "Generic
// Password" / "Generic API Key" style rules, see IsGenericSecretRule) grade
// Suspect/Tentative: secret-shaped but nameless and historically the dominant
// false-positive source, so they stay at the low-signal tier. Downstream grouping
// then folds those generic matches (tagged output.SuspectBundleTag) into a single
// per-host "Low-confidence secret-shaped matches" bundle, while each named family
// keeps its own finding.
//
// From that baseline, several signals can only LOWER severity, applied as a
// ceiling — the returned severity is the LESS severe of the baseline and the
// ceiling, so a downgrade signal never promotes a match above its evidence:
//
//   - A reCAPTCHA site key (recaptchaSiteKey) or Google OAuth client ID
//     (oauthClientID) is Info/Tentative outright, ahead of everything including a
//     (spurious) validation — a public identifier is never a leaked secret.
//   - A live-validated secret is Critical/Certain. The native detector never
//     validates, so this is currently unreachable; kept for completeness.
//   - A match on a redirect (3xx) response, inside a response header value,
//     reflected straight out of the request (SnippetReflectedFromRequest), or
//     served as documentation/demo page content (IsDocDemoSecretContext) caps at
//     Low/Tentative — almost always a low-value reflection or sample.
//   - A Google AIza… API key (googleAPIKey) caps at Medium/Firm (embedded
//     client-side by design; the risk is billing/quota abuse, not takeover).
//   - An undecodable "meta" JWT (lowValueJWT) caps at Medium/Tentative.
//
// Named families now baseline at High, so these Medium/Low ceilings do their job:
// a Google AIza key (a named, non-generic rule) caps at Medium, a named family
// reflected out of the request caps at Low, etc. A generic match baselines at
// Suspect, which already sits below every Low/Medium ceiling, so only the Info
// floor (public identifier) can lower it further.
func SecretFindingSeverity(trusted, generic, validated, redirect, inHeader, reflectedFromRequest, docDemoContext, lowValueJWT, recaptchaSiteKey, googleAPIKey, oauthClientID bool) (severity.Severity, severity.Confidence) {
	// Public identifiers outrank everything — never a leaked secret.
	if recaptchaSiteKey || oauthClientID {
		return severity.Info, severity.Tentative
	}
	// A live-validated credential is serious anywhere (unreachable today).
	if validated {
		return severity.Critical, severity.Certain
	}

	// Baseline by rule identity: a recognisable family (trusted or any named
	// provider rule) grades High; only the generic, family-less matchers stay at
	// the low-signal Suspect tier. Trusted (curated high-confidence) keeps Firm;
	// an unverified named family is High but Tentative.
	baseSev, baseConf := severity.High, severity.Tentative
	switch {
	case trusted:
		baseConf = severity.Firm
	case generic:
		baseSev, baseConf = severity.Suspect, severity.Tentative
	}

	// Ceiling from "probably not a live leak" signals (High = no downgrade).
	ceilSev, ceilConf := severity.High, severity.Firm
	switch {
	case redirect || inHeader || reflectedFromRequest || docDemoContext:
		ceilSev, ceilConf = severity.Low, severity.Tentative
	case googleAPIKey:
		ceilSev, ceilConf = severity.Medium, severity.Firm
	case lowValueJWT:
		ceilSev, ceilConf = severity.Medium, severity.Tentative
	}

	// Final = the less-severe of baseline and ceiling.
	if ceilSev < baseSev {
		return ceilSev, ceilConf
	}
	return baseSev, baseConf
}

// docRouteSegments are URL path segments that mark a page as documentation,
// reference material, a manual, or a CLI guide. Content on these routes is
// written for humans to read and copy, so any secret-shaped string is almost
// always an illustrative sample or demo credential rather than a live secret.
var docRouteSegments = map[string]struct{}{
	"doc":           {},
	"docs":          {},
	"documentation": {},
	"reference":     {},
	"references":    {},
	"manual":        {},
	"manuals":       {},
	"guide":         {},
	"guides":        {},
	"cli":           {},
	"tutorial":      {},
	"tutorials":     {},
	"example":       {},
	"examples":      {},
}

// IsDocDemoSecretContext reports whether a secret match should be treated as a
// documentation sample/demo credential rather than a live leak. It is true only
// when both hold: the response was served from a documentation route (see
// isDocumentationRoute) AND it is rendered page content (see
// isDocPageContentType). Both gates matter — a JWT embedded in a JS bundle under
// /docs/_next/static/... is still a real embedded credential, and an API JSON
// response under a docs path may carry a live token — so we only relax severity
// for the human-readable page itself.
func IsDocDemoSecretContext(rawURL, contentType string) bool {
	if !isDocPageContentType(contentType) {
		return false
	}
	return isDocumentationRoute(rawURL)
}

// isDocumentationRoute reports whether any path segment of rawURL names a
// documentation/reference/manual/CLI route (see docRouteSegments). Matching is
// per-segment so "/cli/" hits but "client" does not, and case-insensitive.
// Callers pass an absolute request URL; a parse failure or empty path simply
// yields no matching segment.
func isDocumentationRoute(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(strings.ToLower(u.Path), "/") {
		if _, ok := docRouteSegments[seg]; ok {
			return true
		}
	}
	return false
}

// isDocPageContentType reports whether contentType is rendered, human-readable
// page content: HTML/XHTML (via the shared modkit.ClassifyContentType) or the
// Next.js React Server Component payload (text/x-component) that carries the same
// server-rendered documentation page for a `?_rsc=` navigation request — which
// classifies as plain text, so it needs its own clause. Bundled scripts,
// stylesheets, and JSON APIs are excluded — a secret in those is more likely a
// real embedded credential.
func isDocPageContentType(contentType string) bool {
	if modkit.ClassifyContentType(contentType) == modkit.ContentClassHTML {
		return true
	}
	return strings.Contains(strings.ToLower(contentType), "x-component")
}

// IsRedirectStatus reports whether code is an HTTP 3xx redirect status.
func IsRedirectStatus(code int) bool {
	return code >= 300 && code < 400
}

// JoinHeaderValues concatenates response header values into a single
// newline-delimited blob suitable for snippet containment checks. Header names
// are omitted — only the values can carry a reflected secret (e.g. a Location
// redirect URL).
func JoinHeaderValues(headers []httpmsg.HttpHeader) string {
	if len(headers) == 0 {
		return ""
	}
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(h.Value)
		b.WriteByte('\n')
	}
	return b.String()
}

// SnippetInHeaderValues reports whether the matched secret snippet appears
// verbatim within the response header values blob (see JoinHeaderValues), most
// commonly a Location redirect URL. the detector only scans response bodies, but
// a server's default redirect body echoes the Location URL, so a header-borne
// value surfaces in the body too; matching it back to a header marks it as a
// low-value reflection rather than leaked page content. A blank snippet never
// matches.
func SnippetInHeaderValues(snippet, headerValues string) bool {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" || headerValues == "" {
		return false
	}
	return strings.Contains(headerValues, snippet)
}

// SnippetReflectedFromRequest reports whether the matched secret snippet appears
// verbatim in the request that produced the response — its URL (path or query)
// or anywhere in the raw request bytes.
//
// A value the client itself sent and the server merely echoed into the page is
// a reflection of client-supplied input, not a server-held secret newly leaked
// to the reader. The dominant case is single-sign-on login flows: a Cloudflare
// Access application id sits in the /cdn-cgi/access/verify-code/<app-id> URL and
// is reflected into the login page body, where a generic Cloudflare-token rule
// matches it. The value came from the request, so the client already had it;
// the body reflection is not a new leak, and the match is downgraded rather than
// reported as a High-severity secret. A blank snippet never matches.
func SnippetReflectedFromRequest(snippet, requestURL, rawRequest string) bool {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" {
		return false
	}
	if requestURL != "" && strings.Contains(requestURL, snippet) {
		return true
	}
	return rawRequest != "" && strings.Contains(rawRequest, snippet)
}
