package web_cache_poisoning

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "web-cache-poisoning"
	ModuleName  = "Web Cache Poisoning"
	ModuleShort = "Detects web cache poisoning via unkeyed header injection"
)

var (
	ModuleDesc = `**What it means:** The application reflects an unkeyed request header (such as X-Forwarded-Host or X-Original-URL) into a cached response, even though the header is not part of the cache key. One attacker request can poison the copy served to every visitor.

**How it's exploited:** A malicious header (e.g. X-Forwarded-Host pointing at the attacker's domain) is reflected into the cached body or Location header and replayed to all users, enabling redirects, script loading, or defacement. Confirmed only on shared-cacheable responses.

**Fix:** Add reflected unkeyed headers to the cache key (Vary), strip untrusted forwarding headers at the edge, or mark responses uncacheable.`

	ModuleConfirmation = "Confirmed when unkeyed header values are reflected in a genuinely shared-cacheable response, indicating cache-poisoning potential"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cache-poisoning", "header-security", "moderate"}
)
