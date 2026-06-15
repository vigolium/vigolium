package xss_stored

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xss-stored"
	ModuleName  = "Stored XSS (browser-confirmed)"
	ModuleShort = "Injects a canary, then confirms it executes on a later retrieval of the page"
)

var (
	ModuleDesc = `**What it means:** The application stores attacker input and later renders it as live HTML/JavaScript, so injected script runs for anyone who views the page. Browser-confirmed: a canary persisted on a clean re-fetch and fired a JavaScript dialog in a headless browser.

**How it's exploited:** An attacker submits malicious script once; it is saved server-side and served to every later visitor, executing in their authenticated session with no per-victim interaction. This enables session theft, account takeover, and worm-like spread.

**Fix:** Contextually output-encode stored user input when rendering, apply server-side validation, and enforce a restrictive Content-Security-Policy.`

	ModuleConfirmation = "Confirmed when an injected payload persists and executes JavaScript on a subsequent retrieval of the page"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xss", "stored"}
)
