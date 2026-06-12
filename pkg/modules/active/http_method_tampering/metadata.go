package http_method_tampering

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "http-method-tampering"
	ModuleName  = "HTTP Method Tampering"
	ModuleShort = "Detects unexpectedly enabled HTTP methods and method override headers"
)

var (
	ModuleDesc = `**What it means:** This endpoint accepts write-oriented HTTP methods (PUT, DELETE, PATCH, MKCOL, MOVE, COPY) that a normal read endpoint should reject, or it honors a method-override header (X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override) that silently changes a POST into a different verb. The scanner confirms this by sending the method and requiring a successful, meaningful, non-shell response, or by showing the override materially changes the reply versus a plain POST control.

**How it's exploited:** An attacker can invoke these verbs to modify or delete resources, or use the override header to reach a more privileged method while bypassing access controls and WAF or proxy rules that only filter on the visible verb. This finding is reported at low severity because enabled methods are often non-exploitable alone and need manual confirmation, but they can become a real write or auth-bypass primitive against a sensitive endpoint.

**Fix:** Restrict each endpoint to only the HTTP methods it requires, disable unused verbs server-side, and stop honoring method-override headers unless they are strictly necessary and access-controlled.`

	ModuleConfirmation = "Confirmed when dangerous HTTP methods return successful, non-shell responses, or a method override header materially changes the response versus a plain POST control"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
