package cors_vary_origin_missing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-vary-origin-missing"
	ModuleName  = "CORS Vary Origin Missing"
	ModuleShort = "Detects dynamic CORS responses missing Vary: Origin header enabling cache poisoning"
)

var (
	ModuleDesc = `**What it means:** The server reflects the request's Origin header back into its Access-Control-Allow-Origin response header but does not send Vary: Origin. Because the CORS header changes per origin while the cache key does not, a shared cache (CDN, reverse proxy) can store one origin's response and serve it to requests from a different origin, which is a web cache poisoning condition.

**How it's exploited:** An attacker primes the cache from their own malicious origin so the cached response carries an Access-Control-Allow-Origin that names their site; victims then receive that response, letting the attacker's page read cross-origin data. When Access-Control-Allow-Credentials: true is also present, the poisoned response can expose authenticated, credentialed data, sharply raising impact.

**Fix:** Add Vary: Origin to every response that reflects the Origin into Access-Control-Allow-Origin (or serve a fixed allow-list of origins), and exclude such credentialed CORS responses from shared caching.`

	ModuleConfirmation = "Confirmed when a response reflects the request Origin into ACAO but omits the Vary: Origin header required for correct shared-cache behavior"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "cache-poisoning", "light"}
)
