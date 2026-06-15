package secret_detect

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// SecretFindingSeverity computes the severity and confidence for a Kingfisher
// secret finding based on where and how it was observed.
//
// A secret that Kingfisher validated as live stays Critical/Certain no matter
// where it appears — a confirmed live credential is serious anywhere. For
// unvalidated matches the baseline is High/Firm, with several downgrades:
//
//   - A reCAPTCHA site key (recaptchaSiteKey — see IsReCaptchaSiteKey) drops to
//     Info/Tentative. Site keys are public by design — embedded in page HTML/JS
//     so the widget can render — so this outranks every other branch, including
//     a (spurious) validation: a public key is never a leaked secret.
//
//   - Matches that ride on a redirect (3xx) response or that appear verbatim
//     inside a response header value drop to Low/Tentative. Those are almost
//     always low-value reflections — e.g. an OAuth client_id / state / nonce
//     embedded in a Location URL that merely bounces the browser to an SSO login
//     page — rather than a genuinely leaked secret served in page content.
//
//   - A Google API key (googleAPIKey — see IsGoogleAPIKey) drops to Medium/Firm.
//     The AIza… key family is routinely embedded in client-side code by design,
//     so leakage is billing/quota abuse against the enabled Google APIs rather
//     than account takeover. A live-validated Google key still escalates ahead of
//     this to Critical.
//
//   - A JWT we cannot decode into a usable credential (lowValueJWT — see
//     LowValueJWT) drops to Medium/Tentative. This catches Cloudflare Access and
//     similar SSO pre-auth "meta" tokens that are embedded in login-page URLs and
//     reflected into the page body: they decode to an unauthenticated metadata
//     token (auth_status=NONE, no identity), not a leaked secret.
func SecretFindingSeverity(validated, redirect, inHeader, lowValueJWT, recaptchaSiteKey, googleAPIKey bool) (severity.Severity, severity.Confidence) {
	switch {
	case recaptchaSiteKey:
		return severity.Info, severity.Tentative
	case validated:
		return severity.Critical, severity.Certain
	case redirect || inHeader:
		return severity.Low, severity.Tentative
	case googleAPIKey:
		return severity.Medium, severity.Firm
	case lowValueJWT:
		return severity.Medium, severity.Tentative
	default:
		return severity.High, severity.Firm
	}
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
// commonly a Location redirect URL. Kingfisher only scans response bodies, but
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
