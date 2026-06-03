package cors_vary_origin_missing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-vary-origin-missing"
	ModuleName  = "CORS Vary Origin Missing"
	ModuleShort = "Detects dynamic CORS responses missing Vary: Origin header enabling cache poisoning"
)

var (
	ModuleDesc = `## Description
Detects responses with a dynamic Access-Control-Allow-Origin header that are missing
the Vary: Origin header. When a server reflects a specific origin in ACAO without
including Vary: Origin, shared caches may serve the response to requests from different
origins, enabling cache poisoning attacks.

## Notes
- Flags responses where ACAO is a specific origin (not wildcard) without Vary: Origin
- Access-Control-Allow-Credentials: true is noted as amplifying cache poisoning risk
- Cache poisoning with credentials amplifies the impact significantly
- Complements CORS header detection with cache-specific misconfiguration checks

## References
- https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
- https://www.w3.org/TR/cors/#resource-implementation`

	ModuleConfirmation = "Confirmed when a dynamic CORS response lacks the Vary: Origin header required for correct cache behavior"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "cache-poisoning", "light"}
)
