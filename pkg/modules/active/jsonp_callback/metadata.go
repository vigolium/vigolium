package jsonp_callback

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-jsonp-callback"
	ModuleName  = "JSONP Callback Injection"
	ModuleShort = "Detects JSONP endpoints that allow cross-origin data theft via callback injection"
)

var (
	ModuleDesc = `## Description
Detects JSONP (JSON with Padding) endpoints that wrap responses in callback
functions, enabling cross-origin data theft. First checks for existing JSONP
patterns in responses, then actively injects callback parameters.

## Notes
- Two-phase detection: passive check for existing JSONP, then active callback injection
- Severity upgraded from Medium to High if response contains sensitive data
- Tests multiple common callback parameter names
- Deduplicates by host + path

## References
- https://owasp.org/www-community/attacks/Cross_Site_Script_Inclusion
- https://www.benhayak.com/2015/06/same-origin-method-execution-some.html`

	ModuleConfirmation = "Confirmed when injecting a callback parameter causes the response to be wrapped in the specified function call"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "info-disclosure", "moderate"}
)
