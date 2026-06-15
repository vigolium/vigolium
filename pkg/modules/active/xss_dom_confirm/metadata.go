package xss_dom_confirm

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xss-dom-confirm"
	ModuleName  = "XSS DOM Confirm (Browser)"
	ModuleShort = "Confirms reflected and DOM-based XSS by observing alert() in a real browser"
)

var (
	ModuleDesc = `**What it means:** A browser-confirmed cross-site scripting (XSS) flaw: a URL query parameter or path segment reflects into the page or flows into a DOM sink, running attacker JavaScript in the victim's browser. The scanner injected an svg/onload=alert(canary) payload and watched a JavaScript dialog fire in a real headless browser.

**How it's exploited:** An attacker lures a victim to a crafted link carrying the payload. On load, the script runs in the site origin, enabling session/token theft, account takeover, or defacement.

**Fix:** Contextually encode URL-derived data on output, avoid dangerous DOM sinks (innerHTML, document.write, eval), and enforce a strict Content-Security-Policy.`

	ModuleConfirmation = "Confirmed when a payload navigated through a real browser triggers a JavaScript dialog (alert/confirm/prompt) whose message contains the unique scan canary"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"xss", "dom-xss", "browser", "slow"}
)
