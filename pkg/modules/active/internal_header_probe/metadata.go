package internal_header_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "internal-header-probe"
	ModuleName  = "Internal Header Probe"
	ModuleShort = "Fuzzes custom/internal request headers advertised via Access-Control-Allow-Headers and reports value-dependent response changes"
)

var (
	ModuleDesc = `**What it means:** The server's CORS response (Access-Control-Allow-Headers / Access-Control-Expose-Headers) advertises a private, usually gateway-injected header protocol — identity, routing, and trust headers such as X-Netflix.user.id or X-Netflix.oauth.token — and supplying a value for one of them reproducibly changes the backend's response. This is an exploratory signal that the backend trusts a client-supplied value for a header meant to be set internally; it is not a confirmed vulnerability and is reported as Suspect / Tentative.

**How it's exploited:** Because the edge passes the client-controlled header through to the backend, an attacker may be able to forge identity, escalate privilege (admin/internal/root values), reach internal routing or feature-flag logic, or smuggle a callback URL for blind SSRF. The disclosed header names also map otherwise-hidden internal attack surface. The body change only proves the value is processed; the concrete impact needs manual verification.

**Fix:** Have the trusted gateway strip or overwrite these internal headers on inbound client requests so the backend never reads attacker-supplied values, and stop advertising them in CORS responses.`

	ModuleConfirmation = "Confirmed when an advertised custom header, set to a probe value, reproducibly shifts the response body beyond the endpoint's natural variance AND to a substantially larger size than the no-header baseline, on an actionable response (2xx/401/5xx, non-blank; 3xx and other 4xx ignored), value stripped to exclude reflection"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cors", "header", "recon", "ssrf", "intrusive"}
)
