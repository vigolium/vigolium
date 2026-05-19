package xss_dom_confirm

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xss-dom-confirm"
	ModuleName  = "XSS DOM Confirm (Browser)"
	ModuleShort = "Confirms reflected and DOM-based XSS by observing alert() in a real browser"
)

var (
	ModuleDesc = `## Description
Browser-confirmed XSS module. After a cheap pattern-matching pre-filter (response
reflection or DOM source-to-sink heuristics) flags a candidate, the module loads
the payload-armed URL in a real headless browser and observes JavaScript dialogs
(alert/confirm/prompt). A confirmed match means JavaScript actually executed —
no string-reflection guesswork.

## Notes
- Pre-filter runs first: never opens the browser unless reflection or a DOM
  source-to-sink pattern is present. Every pre-filter check is a single HTTP
  request the same as a regular reflected-XSS probe.
- Limited to URL-side insertion points (query params, path) where browser
  navigation can naturally carry the payload.
- Each confirmation spins up an isolated browser session via spitolas.ProbeURL,
  bounded by per-host and per-scan budgets.
- Uses a unique canary in the alert message so cross-talk from unrelated alerts
  is not mistaken for confirmation.

## References
- https://owasp.org/www-community/attacks/DOM_Based_XSS
- https://portswigger.net/web-security/cross-site-scripting/dom-based`

	ModuleConfirmation = "Confirmed when a payload navigated through a real browser triggers a JavaScript dialog (alert/confirm/prompt) whose message contains the unique scan canary"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"xss", "dom-xss", "browser", "slow"}
)
