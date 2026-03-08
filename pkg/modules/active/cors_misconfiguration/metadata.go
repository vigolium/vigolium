package cors_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-cors-misconfiguration"
	ModuleName  = "CORS Misconfiguration"
	ModuleShort = "Detects permissive CORS policies allowing unauthorized cross-origin access"
)

var (
	ModuleDesc = `## Description
Detects CORS (Cross-Origin Resource Sharing) misconfigurations that allow unauthorized
cross-origin access. Tests for reflected origins, null origin acceptance, wildcard with
credentials, and subdomain bypass patterns.

## Notes
- Runs once per host with internal deduplication
- Sends 4 probes with different Origin headers per host
- Low false-positive rate due to strict header matching

## References
- https://portswigger.net/web-security/cors
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing`

	ModuleConfirmation = "Confirmed when the server reflects a controlled Origin value in the Access-Control-Allow-Origin header, indicating permissive CORS policy"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
