package http_method_tampering

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "http-method-tampering"
	ModuleName  = "HTTP Method Tampering"
	ModuleShort = "Detects unexpectedly enabled HTTP methods and method override headers"
)

var (
	ModuleDesc = `**What it means:** This endpoint accepts write-oriented HTTP methods (PUT, DELETE, PATCH, MKCOL, MOVE, COPY) a read endpoint should reject, or honors a method-override header (X-HTTP-Method-Override, X-Method-Override) that silently turns a POST into another verb.

**How it's exploited:** An attacker invokes these verbs to modify or delete resources, or uses the override header to reach a privileged method, bypassing access controls and WAF rules that filter only the visible verb. Low severity since it often needs manual confirmation.

**Fix:** Restrict each endpoint to the methods it needs, disable unused verbs server-side, and stop honoring method-override headers unless strictly necessary.`

	ModuleConfirmation = "Confirmed when dangerous HTTP methods return successful, non-shell responses, or a method override header materially changes the response versus a plain POST control"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
