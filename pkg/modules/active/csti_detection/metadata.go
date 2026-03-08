package csti_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-csti-detection"
	ModuleName  = "Client-Side Template Injection (CSTI)"
	ModuleShort = "Detects client-side template injection in AngularJS/Vue.js applications"
)

var (
	ModuleDesc = `## Description
Detects Client-Side Template Injection vulnerabilities by injecting template expressions
(e.g., {{7*7}}) and checking if the expression is reflected literally (not HTML-encoded)
in the response body within a client-side template framework scope.

## Notes
- Different from server-side SSTI: checks for literal reflection, not evaluation
- Fingerprints AngularJS and Vue.js frameworks per-host (cached)
- Only scans hosts where a client-side template framework is detected
- Verifies the expression is not HTML-encoded (which would prevent exploitation)
- Uses double confirmation with random anchors to reduce false positives

## References
- https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs
- https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection`

	ModuleConfirmation = "Confirmed when injected template expressions (e.g., {{7*7}}) are reflected literally in the HTML response within a client-side framework scope"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"angular", "xss", "injection", "ssti", "moderate"}
)
