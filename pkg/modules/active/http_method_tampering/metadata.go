package http_method_tampering

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "http-method-tampering"
	ModuleName  = "HTTP Method Tampering"
	ModuleShort = "Detects unexpectedly enabled HTTP methods and method override headers"
)

var (
	ModuleDesc = `## Description
Tests if dangerous HTTP methods (PUT, DELETE, PATCH) are unexpectedly enabled on endpoints,
and whether method override headers (X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override)
allow changing server behavior.

## Notes
- On 2xx endpoints: tests if PUT/DELETE/PATCH return 2xx with a meaningful, non-shell body
- Tests method override headers via POST with override header set to DELETE/PUT
- The override is only reported when it materially CHANGES the response relative
  to a plain POST control (no override header) — an ignored override that returns
  the same page (e.g. an empty 200 from an SSO/auth endpoint) is not a finding
- Body-meaningfulness is judged against the response BODY, not the full raw
  response, so a body-less 200 wrapped in large headers (CSP, etc.) is not "successful"
- Complementary to forbidden_bypass which focuses on 401/403 endpoints
- Rate-limited per host to avoid excessive probing
- Reported at "suspect" severity: method tampering is frequently non-exploitable
  on its own and warrants manual confirmation

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
- https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when dangerous HTTP methods return successful, non-shell responses, or a method override header materially changes the response versus a plain POST control"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
