package reflected_ssti

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "reflected-ssti"
	ModuleName  = "Reflected SSTI"
	ModuleShort = "Detects SSTI via math expression evaluation"
)

var (
	ModuleDesc = `## Description
Detects Server-Side Template Injection vulnerabilities by injecting math expressions
(e.g., {{7*7}}) and checking if the computed result appears in the response.

## Notes
- Tests multiple template engine syntaxes (Jinja2, Twig, Freemarker, etc.)
- Uses unique random values to avoid false positives from cached responses
- Confirmed by matching computed mathematical results in the response

## References
- https://portswigger.net/research/server-side-template-injection`

	ModuleConfirmation = "Confirmed when injected math expressions (e.g., {{7*7}}=49) are evaluated and the computed result appears in the response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "ssti", "moderate"}
)
