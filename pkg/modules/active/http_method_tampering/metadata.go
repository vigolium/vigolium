package http_method_tampering

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "http-method-tampering"
	ModuleName  = "HTTP Method Tampering"
	ModuleShort = "Observes declared write methods and safely confirms OPTIONS override capability"
)

var (
	ModuleDesc = `**What it means:** OPTIONS advertises write methods, or a safe GET-to-OPTIONS override is honored. This is a capability observation; no state-changing method is sent.

**How it's exploited:** If authorization differs by method or override handling, an attacker may reach a protected operation. Confirmation requires an unauthorized read, write, or durable state change, not a status difference.

**Fix:** Allow only required methods and disable unnecessary override headers.`

	ModuleConfirmation = "Observation only: write methods are declared or a safe OPTIONS override is reproducibly honored; no state-changing method is invoked"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
