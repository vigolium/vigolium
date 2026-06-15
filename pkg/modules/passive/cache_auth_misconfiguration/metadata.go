package cache_auth_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-auth-misconfiguration"
	ModuleName  = "Cache-Auth Misconfiguration"
	ModuleShort = "Detects cacheable responses with user-specific data missing Vary headers"
)

var (
	ModuleDesc = `**What it means:** A publicly cacheable response (Cache-Control: public or s-maxage) is served through a shared cache (CDN or proxy, shown by Age, X-Cache, CF-Cache-Status) yet carries user-specific data without the matching Vary key - a Set-Cookie without Vary: Cookie, or an Authorization request without Vary: Authorization. The cache keys only on the URL.

**How it's exploited:** An attacker requesting the same URL may receive a cached copy holding another user's session cookie or personalized body, enabling session hijacking or PII leakage.

**Fix:** Mark per-user responses private/no-store, or add Vary: Cookie and Vary: Authorization so the cache keys per credential.`

	ModuleConfirmation = "Heuristic: a shared-cache-served, publicly cacheable response carries a user-specific Set-Cookie/Authorization but lacks the matching Vary header; replay across users to confirm"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"misconfiguration", "cache-poisoning", "session", "light"}
)
