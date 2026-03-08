package jwt_weak_secret

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-jwt-weak-secret"
	ModuleName  = "JWT Weak Secret Detection"
	ModuleShort = "Detects JWTs signed with weak HMAC secrets via offline brute-force"
)

var (
	ModuleDesc = `## Description
Passively detects JWT tokens signed with weak HMAC secrets by performing offline
brute-force against an embedded wordlist of ~104K known weak secrets.

## Notes
- Extracts JWTs from Authorization Bearer headers and cookies
- Only tests HMAC-based algorithms (HS256, HS384, HS512)
- Computes HMAC signatures offline without sending additional requests
- Uses embedded jwt.secrets.list wordlist

## References
- https://portswigger.net/web-security/jwt
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens`

	ModuleConfirmation = "Confirmed when a JWT HMAC signature matches a known weak secret"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"authentication", "cryptography", "session", "moderate"}
)
