package dom_xss_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dom-xss-detect"
	ModuleName  = "DOM XSS Detect"
	ModuleShort = "Detects potential DOM-based XSS patterns in responses"
)

var (
	ModuleDesc = `**What it means:** Inline JavaScript in the page reads attacker-influenceable browser sources (such as location.hash, location.search, document.referrer, window.name, or document.cookie) and passes that data into a dangerous DOM sink (such as innerHTML, document.write, eval, Function, or a location/window.open redirect target). This is a pattern-level indicator of a possible DOM-based XSS or DOM-based open redirect, detected statically without executing the script, so it requires manual confirmation.
**How it's exploited:** An attacker crafts a URL (or sets window.name / a referrer) carrying a malicious value that the page's own script writes into the DOM, executing attacker JavaScript entirely in the victim's browser without ever touching the server. That allows session/cookie theft, account takeover, or, for the redirect variant, sending users to an attacker-controlled site for phishing.
**Fix:** Avoid passing untrusted browser-sourced data into HTML/script/redirect sinks; use safe APIs (textContent, setAttribute) and validate or allowlist any values used in navigation.`

	ModuleConfirmation = "Indicated when response JavaScript contains known source-to-sink patterns that could enable DOM-based XSS"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "javascript", "light"}
)
