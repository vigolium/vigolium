package openredirect_params

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "openredirect-params"
	ModuleName  = "Open Redirect Params"
	ModuleShort = "Detects URL parameters commonly used for open redirects"
)

var (
	ModuleDesc = `## Description
Passively detects URL parameters with names commonly associated with open redirect
vulnerabilities (redirect, url, next, return, goto, etc.).

## Notes
- Pattern-based detection on parameter names only; does not test for actual redirects
- Low confidence; serves as a triage signal for the active open redirect module

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html`

	ModuleConfirmation = "Indicated when URL contains parameters with redirect-associated names (redirect, url, next, return, goto)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"open-redirect", "light"}
)
