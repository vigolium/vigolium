package cors_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-misconfiguration"
	ModuleName  = "CORS Misconfiguration"
	ModuleShort = "Detects permissive CORS policies allowing unauthorized cross-origin access"
)

var (
	ModuleDesc = `**What it means:** The server returns a permissive Cross-Origin Resource Sharing (CORS) policy letting outside origins read its responses, confirmed via Access-Control-Allow-Origin reflecting an attacker-chosen origin, allowing null, pairing wildcard with credentials, or accepting forged subdomain or scheme variants.

**How it's exploited:** An attacker hosts a page that scripts an authenticated cross-origin request. Because the server trusts the attacker's origin, the browser hands the response to attacker JavaScript, leaking session data like API or CSRF tokens.

**Fix:** Validate Origin against a strict allowlist of exact trusted origins, never reflect arbitrary origins, never combine the wildcard with credentials, and reject null.`

	ModuleConfirmation = "Confirmed when the server reflects a controlled Origin value in the Access-Control-Allow-Origin header, indicating permissive CORS policy"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
