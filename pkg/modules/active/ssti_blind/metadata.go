package ssti_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-ssti-blind"
	ModuleName  = "Blind Server-Side Template Injection (SSTI)"
	ModuleShort = "Detects blind SSTI via OAST callbacks and time-delay payloads"
)

var (
	ModuleDesc = `## Description
Detects blind Server-Side Template Injection vulnerabilities using a dual approach:
OAST (Out-of-Band) callbacks via DNS lookups and time-delay payloads as a fallback.
OAST payloads use nslookup to trigger DNS callbacks, while time-delay payloads use
computationally expensive loops to cause measurable response delays.

## Notes
- Dual detection: OAST callbacks (Firm confidence) + time-delay fallback (Tentative confidence)
- OAST payloads target Jinja2, Mako, Freemarker, ERB, EJS, and Pebble engines
- Time-delay payloads target Jinja2, Twig, Mako, ERB, and Freemarker engines
- Time-delay uses triple verification (slow, fast, slow) to reduce false positives
- OAST findings arrive asynchronously via polling callbacks

## References
- https://portswigger.net/research/server-side-template-injection
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-Side_Template_Injection`

	ModuleConfirmation = "Confirmed via OAST DNS callback from template evaluation or consistent time-delay differential"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"injection", "ssti", "heavy"}
)
