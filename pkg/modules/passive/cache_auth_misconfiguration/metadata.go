package cache_auth_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-auth-misconfiguration"
	ModuleName  = "Cache-Auth Misconfiguration"
	ModuleShort = "Detects cacheable responses with user-specific data missing Vary headers"
)

var (
	ModuleDesc = `**What it means:** A publicly cacheable response (Cache-Control: public or s-maxage) is served through a shared cache (a CDN or reverse proxy, proven by headers like Age, X-Cache, or CF-Cache-Status) yet carries user-specific data without the matching Vary key. Either it sets a user-specific Set-Cookie without Vary: Cookie, or it was fetched with an Authorization header without Vary: Authorization. Without those keys the cache stores one copy keyed only on the URL, so one user's personalized response can be served to others. This is a heuristic signal from passive analysis, not a confirmed leak.

**How it's exploited:** An attacker requests the same URL and may receive a cached copy containing another user's session cookie, token, or personalized body, enabling session hijacking or PII disclosure. To confirm, replay the URL as a second user and check whether the cache returns the first user's data (Age greater than 0 or X-Cache: HIT).

**Fix:** Mark per-user responses private/no-store, or add Vary: Cookie and Vary: Authorization so the cache keys on the credential.`

	ModuleConfirmation = "Heuristic: a shared-cache-served, publicly cacheable response carries a user-specific Set-Cookie/Authorization but lacks the matching Vary header; replay across users to confirm"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"misconfiguration", "cache-poisoning", "session", "light"}
)
