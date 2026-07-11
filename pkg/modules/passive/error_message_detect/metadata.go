package error_message_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "error-message-detect"
	ModuleName  = "Error Message Detect"
	ModuleShort = "Observes corroborated framework or database errors in error responses"
)

var (
	ModuleDesc = `**What it means:** An error response contains a technology-specific signature plus an independent error anchor; successful responses require three anchors. Generic tokens never trigger alone. Structured multi-frame traces are left to the dedicated detector.

**How it's exploited:** Leaked errors reveal frameworks, paths, or SQL fragments that guide targeted attacks and may expose an injection side effect.

**Fix:** Disable production debug output, return generic errors, and log detailed traces and database errors only server-side.`

	ModuleConfirmation = "Observed only when a semantic error context contains a category-specific signature and independent corroborating error evidence"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
