package web_cache_poisoning

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "web-cache-poisoning"
	ModuleName  = "Web Cache Poisoning"
	ModuleShort = "Detects web cache poisoning via unkeyed header injection"
)

var (
	ModuleDesc = `**What it means:** A fresh unkeyed-header value appeared in a shared-cacheable response but not the clean baseline. Tests use a unique query key. Reflection is a candidate; repeated header-free replay to a separate client is a finding.

**How it's exploited:** An attacker injects a value that the shared cache stores and serves to later visitors.

**Fix:** Include influential headers in the cache key, strip untrusted forwarding headers, or mark the response uncacheable.`

	ModuleConfirmation = "Candidate on fresh reflection plus explicit cacheability; confirmed only by repeated clean cross-client replay of the injected value"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cache-poisoning", "header-security", "moderate"}
)
