package xss_dom_confirm

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xss-dom-confirm"
	ModuleName  = "XSS DOM Confirm (Browser)"
	ModuleShort = "Confirms reflected and DOM-based XSS by observing alert() in a real browser"
)

var (
	ModuleDesc = `**What it means:** The application has a browser-confirmed cross-site scripting (XSS) flaw: a value from a URL query parameter or path segment is reflected into the page or flows into a DOM sink, letting attacker-supplied JavaScript run in the victim's browser. This is not a guess from string reflection alone; the scanner injected an svg/onload=alert(canary) payload, navigated the URL in a real headless browser, and observed the script actually execute (a JavaScript dialog fired carrying the unique per-scan canary).

**How it's exploited:** An attacker crafts a malicious link with the payload in the vulnerable parameter or path and lures a victim to open it. When the victim's browser loads the page, the script executes in the site's origin, allowing session-cookie or token theft, account takeover, request forgery on behalf of the user, or page defacement. If a WAF fronts the host, the scanner also confirmed the bypass works.

**Fix:** Contextually encode or sanitize all URL-derived data on output, avoid dangerous DOM sinks (innerHTML, document.write, eval), and enforce a strict Content-Security-Policy.`

	ModuleConfirmation = "Confirmed when a payload navigated through a real browser triggers a JavaScript dialog (alert/confirm/prompt) whose message contains the unique scan canary"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"xss", "dom-xss", "browser", "slow"}
)
