package cache_auth_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-auth-misconfiguration"
	ModuleName  = "Cache-Auth Misconfiguration"
	ModuleShort = "Detects cacheable responses with user-specific data missing Vary headers"
)

var (
	ModuleDesc = `## Description
Detects responses that are publicly cacheable (Cache-Control: public or s-maxage) but
contain user-specific indicators (Set-Cookie, Authorization) without proper Vary headers.
This can lead to one user's authenticated response being served from cache to another
user, causing data leakage or session confusion.

## Notes
- Passive only — does not send any HTTP requests
- Skips static assets (JS, CSS, images, fonts)
- Checks for Cache-Control: public or s-maxage without no-store/private
- Reports missing Vary: Cookie when Set-Cookie is present
- Reports missing Vary: Authorization when Authorization header was in request
- Deduplicates by host+path

## References
- https://portswigger.net/web-security/web-cache-poisoning
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary`

	ModuleConfirmation = "Confirmed when a cacheable response has user-specific headers but missing corresponding Vary header"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"misconfiguration", "cache-poisoning", "session", "light"}
)
