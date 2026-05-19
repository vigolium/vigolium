package jwt_weak_secret

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jwt-weak-secret"
	ModuleName  = "JWT Weak Secret Detection"
	ModuleShort = "Detects JWTs with weak HMAC secrets, non-cryptographic signatures, and algorithm confusion"
)

var (
	ModuleDesc = `## Description
Passively detects JWT tokens signed with weak HMAC secrets by performing offline
brute-force against an embedded wordlist of ~104K known weak secrets.

When an asymmetric-algorithm JWT (RS256, ES256, etc.) is found but no HMAC secret
matches, emits a low-severity informational finding noting the potential for
algorithm confusion (CVE-2015-9235). Active testing is recommended to confirm.

## Notes
- Extracts JWTs from Authorization Bearer headers and cookies
- Tests HMAC-based algorithms (HS256, HS384, HS512)
- Detects non-cryptographic (plaintext ASCII) signatures indicating trivially forgeable tokens
- Tests algorithm confusion (CVE-2015-9235): tries HS256/HS384/HS512 brute-force on asymmetric tokens (RS256, ES256, etc.)
- Emits informational finding for asymmetric JWTs even when no weak secret is found
- Computes HMAC signatures offline without sending additional requests
- Uses embedded jwt.secrets.list wordlist

## References
- https://portswigger.net/web-security/jwt
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens`

	ModuleConfirmation = "Confirmed when a JWT HMAC signature matches a known weak secret"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "cryptography", "session", "moderate"}
)
