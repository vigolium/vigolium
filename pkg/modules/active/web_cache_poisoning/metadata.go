package web_cache_poisoning

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "web-cache-poisoning"
	ModuleName  = "Web Cache Poisoning"
	ModuleShort = "Detects web cache poisoning via unkeyed header injection"
)

var (
	ModuleDesc = `**What it means:** The application reflects the value of an unkeyed request header (such as X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, X-Rewrite-URL, X-Forwarded-Port, or Accept-Language) into a response that a shared cache will store, even though that header is not part of the cache key. This means a single attacker-controlled request can poison the cached copy that is then served to every other visitor.

**How it's exploited:** An attacker sends one request carrying a malicious header value (for example X-Forwarded-Host pointing at an attacker domain) that gets reflected into the cached response body or Location header; the poisoned entry is replayed to all users of that cache, enabling redirects to attacker-controlled hosts, malicious script/resource loading, or content defacement. Vigolium confirms reflection and gates on genuine shared-cacheability (cache HIT or an explicit public/s-maxage/max-age directive) and re-confirms via a clean-baseline body differential to avoid uncacheable false positives.

**Fix:** Add reflected unkeyed headers to the cache key (Vary), strip untrusted forwarding headers at the edge, or mark affected responses uncacheable.`

	ModuleConfirmation = "Confirmed when unkeyed header values are reflected in a genuinely shared-cacheable response, indicating cache-poisoning potential"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cache-poisoning", "header-security", "moderate"}
)
