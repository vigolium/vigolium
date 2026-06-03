package mass_assignment

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mass-assignment"
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
- Differential confirmation: only reports when injecting the key actually changes the
  response AND the key is reflected back because of the injection (absent from the
  untouched baseline response)
- Sends a benign canary key first; if the endpoint mirrors that arbitrary field too,
  it reflects all input indiscriminately and no finding is reported
- Skips keys already present in the original request body, and endpoints that simply
  ignore the field (response identical to baseline) or reject it (4xx/validation error)

## References
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/`

	ModuleConfirmation = "Confirmed when injecting a privilege key materially changes the response and the key is reflected back due to the injection (not present in the un-injected baseline), while a benign canary key is not similarly reflected"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "api", "moderate"}
)
