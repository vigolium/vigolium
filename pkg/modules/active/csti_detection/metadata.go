package csti_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csti-detection"
	ModuleName  = "Client-Side Template Injection (CSTI)"
	ModuleShort = "Detects client-side template injection in AngularJS/Vue.js applications"
)

var (
	ModuleDesc = `**What it means:** User input is reflected unescaped into a page running a client-side template framework (AngularJS, Vue.js, Svelte, Alpine.js), which evaluates expressions like {{7*7}} in the browser - a Client-Side Template Injection flaw leading to cross-site scripting.

**How it's exploited:** An attacker crafts a link with a template expression that runs arbitrary JavaScript in the victim's browser, often bypassing a Content Security Policy, enabling session theft and account takeover. Confirmed when a unique {{N*M}} expression reflects literally in the framework's DOM scope.

**Fix:** Treat user input as untrusted data, never interpolate it into templates, and HTML-encode reflected values.`

	ModuleConfirmation = "Confirmed when injected template expressions (e.g., {{7*7}}) are reflected literally in the HTML response within a client-side framework scope"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"angular", "xss", "injection", "ssti", "moderate"}
)
