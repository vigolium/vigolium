package dom_xss_taint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dom-xss-taint"
	ModuleName  = "DOM XSS (taint analysis)"
	ModuleShort = "Reports DOM XSS where a controllable source provably flows into a dangerous sink"
)

var (
	ModuleDesc = `**What it means:** AST taint analysis traces attacker-influenced DOM input (location.hash, location.search, window.name) into a dangerous sink (innerHTML, eval, document.write, Function). A likely DOM-based XSS: untrusted data reaches code the browser executes as markup, with no server round-trip.

**How it's exploited:** An attacker crafts a client-controlled value (such as a malicious URL fragment) and lures the victim to open it; the tainted value hits the sink and attacker script runs in the victim's session, enabling cookie theft or account takeover.

**Fix:** Treat DOM-source data as untrusted: avoid dangerous sinks, use textContent, and sanitize input first.`

	ModuleConfirmation = "Reported when AST taint analysis traces a DOM-controlled source into a dangerous sink within the same script"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "dom", "taint"}
)
