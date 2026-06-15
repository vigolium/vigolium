package postmessage_handler_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "postmessage-handler-detect"
	ModuleName  = "JavaScript postMessage Handler Detected"
	ModuleShort = "Detects window postMessage handlers and wildcard-origin sends in JS"
)

var (
	ModuleDesc = `**What it means:** Served JavaScript registers a window message handler (addEventListener message or window.onmessage), or calls postMessage with a wildcard target origin. Cross-document messaging bypasses the Same-Origin Policy, so these channels need explicit origin handling.

**How it's exploited:** A handler that ignores event.origin trusts messages from any window, including attacker frames, turning message data into DOM XSS or token theft. A wildcard origin lets a page controlling the receiver read the data.

**Fix:** Validate event.origin against an allowlist before using message data, and pass an exact target origin to postMessage, never the wildcard.`

	ModuleConfirmation = "Confirmed when response JavaScript registers a window message handler or calls postMessage with a wildcard target origin"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"postmessage", "dom", "javascript", "light"}
)
