package cache_data_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-data-leak"
	ModuleName  = "Cache Data Leak"
	ModuleShort = "Detects cache and static generation patterns that may leak user data"
)

var (
	ModuleDesc = `**What it means:** This passively inspects served JavaScript/TypeScript bundles for Next.js caching and static-generation code paths that mix per-user, authenticated data with a shared cache. It flags four patterns: getStaticProps that reads session/cookies/auth, a force-static page that imports auth utilities, unstable_cache called without a userId/sessionId key while touching auth data, and a server-component fetch carrying Authorization/cookies without cache no-store or revalidate 0. Because the result is built once and reused for everyone, one user's session-scoped data can be served to other visitors (CWE-524).
**How it's exploited:** An unauthenticated or different user simply requests the cached page or route and receives another user's personalized or authenticated content (profile, tokens, account details), enabling cross-user information disclosure without any crafted attack. This is a source-pattern indicator and should be confirmed by observing leaked data between sessions.
**Fix:** Mark routes that depend on session data as dynamic and uncacheable (force-dynamic, cache no-store, revalidate 0), and scope any cache key to the authenticated user.`

	ModuleConfirmation = "Confirmed when static generation or caching patterns are used alongside authentication-scoped data fetching"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"info-disclosure", "cache-poisoning", "light"}
)
