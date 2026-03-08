package mass_assignment

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-mass-assignment"
	ModuleName  = "Mass Assignment"
	ModuleShort = "Detects mass assignment / parameter pollution in JSON APIs"
)

var (
	ModuleDesc = `## Description
Tests JSON API endpoints for mass assignment vulnerabilities by injecting privilege-related
keys (role, admin, is_admin, permissions, etc.) into POST/PUT/PATCH JSON request bodies
and observing server responses.

## Notes
- Only activates on POST/PUT/PATCH requests with application/json content type
- Injects one privilege key at a time to isolate findings
- Reports firm confidence if server echoes back the injected key in response
- Reports tentative confidence if server accepts the request without error
- Skips keys already present in the original request body

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/`

	ModuleConfirmation = "Confirmed when injected privilege keys are echoed back in server response or accepted without validation error"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"injection", "api", "moderate"}
)
