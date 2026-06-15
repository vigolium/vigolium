package internal_header_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "internal-header-probe"
	ModuleName  = "Internal Header Probe"
	ModuleShort = "Fuzzes custom/internal request headers advertised via Access-Control-Allow-Headers and reports value-dependent response changes"
)

var (
	ModuleDesc = `**What it means:** The CORS response advertises private, gateway-injected identity headers such as X-Netflix.user.id, and supplying a value for one reproducibly changes the backend's response. An exploratory signal the backend trusts a client-supplied internal header; reported as Suspect, not confirmed.

**How it's exploited:** If the edge passes the header through, an attacker may forge identity, escalate privilege, reach internal routing, or smuggle a callback URL for blind SSRF. The disclosed names also map hidden attack surface; impact needs manual verification.

**Fix:** Have the trusted gateway strip these internal headers on inbound requests and stop advertising them in CORS responses.`

	ModuleConfirmation = "Confirmed when an advertised custom header, set to a probe value, reproducibly shifts the response body beyond the endpoint's natural variance AND to a substantially larger size than the no-header baseline, on an actionable response (2xx/401/5xx, non-blank; 3xx and other 4xx ignored), value stripped to exclude reflection"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cors", "header", "recon", "ssrf", "intrusive"}
)
