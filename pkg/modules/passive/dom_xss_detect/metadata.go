package dom_xss_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dom-xss-detect"
	ModuleName  = "DOM XSS Detect"
	ModuleShort = "Detects potential DOM-based XSS patterns in responses"
)

var (
	ModuleDesc = `**What it means:** Inline JavaScript reads an attacker-controllable source (location.hash, location.search, document.referrer, window.name) and passes it to a dangerous DOM sink (innerHTML, document.write, eval, Function). A static pattern indicator of possible DOM-based XSS or open redirect, needing manual confirmation.

**How it's exploited:** A crafted URL makes the page's own script write the value into the DOM, executing attacker JavaScript in the victim's browser with no server round-trip - enabling cookie theft, account takeover, or phishing redirects.

**Fix:** Keep untrusted browser data out of HTML, script, and redirect sinks; use textContent and validate navigation values.`

	ModuleConfirmation = "Indicated when response JavaScript contains known source-to-sink patterns that could enable DOM-based XSS"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "javascript", "light"}
)
