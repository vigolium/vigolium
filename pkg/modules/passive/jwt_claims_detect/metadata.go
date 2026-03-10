package jwt_claims_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jwt-claims-detect"
	ModuleName  = "JWT Claim Analyzer"
	ModuleShort = "Analyzes JWT claims for security misconfigurations"
)

var (
	ModuleDesc = `## Description
Passively analyzes JWT tokens found in request headers, cookies, and response bodies
for security misconfigurations such as algorithm:none, missing expiration, long-lived
tokens, and privileged claims.

## Notes
- Extracts JWTs from Authorization Bearer headers, cookies, and response bodies
- Decodes header and payload without verifying signatures
- Checks for alg:none, missing exp/iss/aud, long-lived tokens, and admin claims
- Does not send additional requests

## References
- https://portswigger.net/web-security/jwt
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens`

	ModuleConfirmation = "Confirmed when JWT claims contain security misconfigurations"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"authentication", "session", "cryptography", "light"}
)
