package cache_auth_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-auth-misconfiguration"
	ModuleName  = "Cache-Auth Misconfiguration"
	ModuleShort = "Detects cacheable responses with user-specific data missing Vary headers"
)

var (
	ModuleDesc = `**What it means:** A public cache hit coincides with a live session or authorization credential but lacks the corresponding Vary token. This is a candidate because caches may segregate responses through other configuration and the body may not be personalized.

**How it's exploited:** A shared cache may replay one user's personalized response to another user. Confirmation requires cross-user replay.

**Fix:** Mark per-user responses private or no-store, or key the cache by Cookie and Authorization.`

	ModuleConfirmation = "Candidate only after an actual cache HIT plus live credential/session evidence and missing Vary token; cross-user replay is required for a finding"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"misconfiguration", "cache-poisoning", "session", "light"}
)
