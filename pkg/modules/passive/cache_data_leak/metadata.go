package cache_data_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-data-leak"
	ModuleName  = "Cache Data Leak"
	ModuleShort = "Detects cache and static generation patterns that may leak user data"
)

var (
	ModuleDesc = `**What it means:** Served Next.js bundles mix per-user authenticated data with a shared cache - getStaticProps reading session/cookies, a force-static page importing auth, unstable_cache without a userId key, or a server fetch with Authorization but no no-store. Built once and reused, one user's data can reach others (CWE-524).

**How it's exploited:** Any visitor requests the cached page and receives another user's content (profile, tokens, account details) - cross-user disclosure with no crafted attack. Confirm by observing leaked data between sessions.

**Fix:** Mark session-dependent routes dynamic and uncacheable (force-dynamic, no-store, revalidate 0) and scope cache keys to the user.`

	ModuleConfirmation = "Confirmed when static generation or caching patterns are used alongside authentication-scoped data fetching"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"info-disclosure", "cache-poisoning", "light"}
)
