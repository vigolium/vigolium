package css_injection_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "css-injection-detect"
	ModuleName  = "CSS Injection (reflected into style context)"
	ModuleShort = "Flags request values reflected into a <style> block or style= attribute"
)

var (
	ModuleDesc = `**What it means:** A request parameter value is reflected into a CSS context in the response — inside a <style> block or a style="" attribute — where it can break out of the intended rule. This is a CSS-injection surface distinct from HTML XSS.

**How it's exploited:** An attacker injects CSS that exfiltrates data via attribute selectors and background:url() callbacks, overlays or defaces the page, or uses dangling-markup to capture CSRF tokens — without executing script.

**Fix:** Contextually encode values placed into CSS, never inject untrusted input into style contexts, and restrict style-src with a strict Content-Security-Policy.`

	ModuleConfirmation = "Reported when a non-trivial request parameter value appears inside a <style> block or a style= attribute in the response body"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"client-side", "css-injection", "reflection", "light"}
)
