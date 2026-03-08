package http_method_tampering

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-http-method-tampering"
	ModuleName  = "HTTP Method Tampering"
	ModuleShort = "Detects unexpectedly enabled HTTP methods and method override headers"
)

var (
	ModuleDesc = `## Description
Tests if dangerous HTTP methods (PUT, DELETE, PATCH) are unexpectedly enabled on endpoints,
and whether method override headers (X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override)
allow changing server behavior.

## Notes
- On 2xx endpoints: tests if PUT/DELETE/PATCH return 2xx with meaningful body
- Tests method override headers via POST with override header set to DELETE/PUT
- Complementary to forbidden_bypass which focuses on 401/403 endpoints
- Rate-limited per host to avoid excessive probing

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
- https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when dangerous HTTP methods return successful responses or method override headers alter server behavior"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
