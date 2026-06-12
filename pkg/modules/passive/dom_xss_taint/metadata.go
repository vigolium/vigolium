package dom_xss_taint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dom-xss-taint"
	ModuleName  = "DOM XSS (taint analysis)"
	ModuleShort = "Reports DOM XSS where a controllable source provably flows into a dangerous sink"
)

var (
	ModuleDesc = `**What it means:** The page contains client-side JavaScript where attacker-influenced input from a DOM source (such as location.hash, location.search, document.cookie, window.name, or local/session storage) flows, via AST taint analysis, into a dangerous sink (such as innerHTML, eval, document.write, insertAdjacentHTML, or Function). This is a likely DOM-based cross-site scripting (XSS) condition: untrusted data reaches a place where the browser executes it as markup or code, with no server round-trip needed.

**How it's exploited:** An attacker crafts a URL or other client-controlled value (for example a malicious fragment after the # in the link) and lures a victim to open it; when the page runs, the tainted value is written into the sink and the attacker's script executes in the victim's session, enabling session-cookie theft, account takeover, or actions performed as the user.

**Fix:** Treat all DOM-source data as untrusted: avoid dangerous sinks, use textContent or safe DOM APIs, and contextually encode or sanitize input before it reaches any HTML or code sink.`

	ModuleConfirmation = "Reported when AST taint analysis traces a DOM-controlled source into a dangerous sink within the same script"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "dom", "taint"}
)
