package cache_data_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-data-leak"
	ModuleName  = "Cache Data Leak"
	ModuleShort = "Detects cache and static generation patterns that may leak user data"
)

var (
	ModuleDesc = `## Description
Scans JavaScript and TypeScript response bodies for Next.js caching and static
generation patterns that may inadvertently leak authenticated or user-specific data.
Static pages (getStaticProps, force-static) are generated at build time and served
to all users, so including session-dependent data causes cross-user data leakage.
Similarly, unstable_cache without user-scoped keys or server fetches without
cache: "no-store" may serve stale authenticated responses to different users.

## Notes
- Passive only - does not send any HTTP requests
- Detects: getStaticProps with auth, force-static with auth, unstable_cache without user key
- Also detects server component fetches with auth headers but without no-store/revalidate:0
- CWE-524: Use of Cache That Contains Sensitive Information
- Deduplicates by host+path

## References
- https://nextjs.org/docs/app/building-your-application/caching
- https://nextjs.org/docs/app/building-your-application/data-fetching
- https://cwe.mitre.org/data/definitions/524.html`

	ModuleConfirmation = "Confirmed when static generation or caching patterns are used alongside authentication-scoped data fetching"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"info-disclosure", "cache-poisoning", "light"}
)
