package csti_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csti-detection"
	ModuleName  = "Client-Side Template Injection (CSTI)"
	ModuleShort = "Detects client-side template injection in AngularJS/Vue.js applications"
)

var (
	ModuleDesc = `**What it means:** User-supplied input is reflected unescaped into the HTML of a page that runs a client-side JavaScript template framework (AngularJS, Vue.js, Svelte, or Alpine.js). Because the framework evaluates template expressions like {{7*7}} in the victim's browser, attacker-controlled input becomes executable template code, which is a Client-Side Template Injection (CSTI) flaw that leads to cross-site scripting.

**How it's exploited:** An attacker crafts a link or form input containing a template expression that the framework evaluates in the victim's browser, breaking out of the data context to run arbitrary JavaScript even where a Content Security Policy blocks classic script injection; this enables session/cookie theft, account takeover, and actions performed as the victim. The scanner confirms the issue by injecting a uniquely anchored {{N*M}} expression and verifying it is reflected literally (not HTML-encoded) inside the detected framework's DOM scope.

**Fix:** Treat user input as untrusted data, never interpolate it into framework templates, and HTML-encode all reflected values.`

	ModuleConfirmation = "Confirmed when injected template expressions (e.g., {{7*7}}) are reflected literally in the HTML response within a client-side framework scope"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"angular", "xss", "injection", "ssti", "moderate"}
)
