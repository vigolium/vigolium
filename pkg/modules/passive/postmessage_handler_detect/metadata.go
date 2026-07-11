package postmessage_handler_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "postmessage-handler-detect"
	ModuleName  = "JavaScript postMessage Handler Detected"
	ModuleShort = "Detects window postMessage handlers and wildcard-origin sends in JS"
)

var (
	ModuleDesc = `**What it means:** Served JavaScript registers a window message handler or sends to a wildcard target origin. Validated/named handlers and same-window sends are observations; unchecked inline handlers and cross-document wildcard sends are candidates.

**How it's exploited:** Exploitation additionally requires attacker window reachability plus a sensitive payload or a message-data flow into a dangerous sink. Regex proximity cannot prove those conditions, so it never confirms XSS or token theft.

**Fix:** Validate event.origin against an allowlist before using message data, and pass an exact target origin to postMessage, never the wildcard.`

	ModuleConfirmation = "Observation for messaging primitives; candidate for unchecked inline handlers or cross-document wildcard sends, pending connected payload/sink analysis"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"postmessage", "dom", "javascript", "light"}
)
