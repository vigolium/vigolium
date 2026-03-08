package angular_template_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-angular-template-injection"
	ModuleName  = "Angular Template Injection"
	ModuleShort = "Detects Angular template injection via expression evaluation"
)

var (
	ModuleDesc = `## Description
Detects Angular template injection vulnerabilities by injecting math expressions inside
Angular template syntax (e.g., {{7*7}}) and checking if the computed result appears in
the response. This indicates the Angular engine is evaluating user-controlled expressions,
which can lead to arbitrary JavaScript execution.

## Notes
- Tests basic Angular expression evaluation ({{mathA*mathB}})
- Tests Angular 1.x sandbox bypass via constructor chain
- Uses double confirmation with random math anchors to reduce false positives
- Each confirmation attempt uses different random values
- Checks that computed result appears in response but not in baseline

## References
- https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs
- https://github.com/nicedayzhu/angular-sandbox-bypass-collection`

	ModuleConfirmation = "Confirmed when injected Angular math expressions are evaluated and the computed result appears in the response across multiple attempts"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"angular", "injection", "ssti", "moderate"}
)
