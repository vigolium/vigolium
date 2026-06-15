package cors_vary_origin_missing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-vary-origin-missing"
	ModuleName  = "CORS Vary Origin Missing"
	ModuleShort = "Detects dynamic CORS responses missing Vary: Origin header enabling cache poisoning"
)

var (
	ModuleDesc = `**What it means:** The server reflects the request's Origin into Access-Control-Allow-Origin but omits Vary: Origin. The CORS header varies per origin while the cache key does not, so a shared cache (CDN, proxy) can store one origin's response and serve it to another - web cache poisoning.

**How it's exploited:** An attacker primes the cache from a malicious origin so the cached response names their site; victims receive it, letting the attacker's page read cross-origin data. With Access-Control-Allow-Credentials: true, authenticated data leaks.

**Fix:** Add Vary: Origin wherever the Origin is reflected, and exclude credentialed CORS responses from shared caching.`

	ModuleConfirmation = "Confirmed when a response reflects the request Origin into ACAO but omits the Vary: Origin header required for correct shared-cache behavior"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "cache-poisoning", "light"}
)
