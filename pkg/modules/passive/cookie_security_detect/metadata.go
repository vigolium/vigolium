package cookie_security_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cookie-security-detect"
	ModuleName  = "Cookie Security Detect"
	ModuleShort = "Detects insecure cookie attributes in HTTP responses"
)

var (
	ModuleDesc = `## Description
Passively detects insecure cookie configurations by analyzing Set-Cookie headers
for missing Secure, HttpOnly, and SameSite attributes.

## Notes
- Checks all Set-Cookie headers in responses
- Flags cookies missing Secure flag on HTTPS responses
- Flags cookies missing HttpOnly attribute
- Flags cookies without SameSite attribute

## References
- https://owasp.org/www-community/controls/SecureCookieAttribute
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when Set-Cookie headers lack Secure, HttpOnly, or SameSite attributes"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"session", "misconfiguration", "header-security", "light"}
)
