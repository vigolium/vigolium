package xss_stored

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xss-stored"
	ModuleName  = "Stored XSS (browser-confirmed)"
	ModuleShort = "Injects a canary, then confirms it executes on a later retrieval of the page"
)

var (
	ModuleDesc = `**What it means:** The application stores attacker-supplied input and later renders it into a page as live HTML/JavaScript instead of inert text, so injected script runs in the browser of anyone who views that page. This was browser-confirmed: a unique canary payload was submitted through this parameter, found to persist when the page was re-fetched with a clean request that carried no payload, and then observed actually executing (firing a JavaScript dialog with the canary) when the stored page was loaded in a real headless browser.

**How it's exploited:** An attacker submits a malicious script once; it is saved server-side and served to every later visitor, executing in their authenticated session without any per-victim interaction. This enables session/cookie theft, account takeover, credential phishing, and worm-like spread across users who simply view the affected page.

**Fix:** Contextually output-encode all stored user input when rendering it and apply server-side input validation, backed by a restrictive Content-Security-Policy.`

	ModuleConfirmation = "Confirmed when an injected payload persists and executes JavaScript on a subsequent retrieval of the page"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xss", "stored"}
)
