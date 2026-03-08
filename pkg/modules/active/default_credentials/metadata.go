package default_credentials

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-default-credentials"
	ModuleName  = "Default Credentials"
	ModuleShort = "Tests for default or common credential pairs on login endpoints"
)

var (
	ModuleDesc = `## Description
Detects login endpoints from observed traffic and tests them with common default credential
pairs. Uses intelligent login form detection, CAPTCHA awareness, and lockout protection.

## Notes
- Only tests POST requests with form-encoded or JSON bodies
- Detects login endpoints by matching parameter names and URL paths
- Sends baseline invalid credentials first to establish failure response
- Stops on first successful login or lockout detection
- 500ms delay between credential attempts to avoid rate limiting
- Preserves CSRF tokens and hidden form fields during testing

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials`

	ModuleConfirmation = "Confirmed when a known credential pair produces a response significantly different from the invalid-credential baseline, indicating successful authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
