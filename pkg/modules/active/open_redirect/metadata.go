package open_redirect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "open-redirect"
	ModuleName  = "Open Redirect"
	ModuleShort = "Detects open redirect vulnerabilities"
)

var (
	ModuleDesc = `## Description
Detects open redirect vulnerabilities by injecting external URLs into parameters
and checking if the server responds with a redirect to the injected location.

## Notes
- Tests parameters for unvalidated redirect behavior
- Checks both Location header and meta refresh redirects
- Uses request deduplication to avoid redundant checks

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when injected external URL appears in a redirect Location header or meta refresh tag"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"open-redirect", "moderate"}
)
