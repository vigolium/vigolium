package host_header_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-host-header-injection"
	ModuleName  = "Host Header Injection"
	ModuleShort = "Detects host header injection and routing manipulation"
)

var (
	ModuleDesc = `## Description
Detects host header injection vulnerabilities by manipulating the Host header and
related headers (X-Forwarded-Host, X-Host) to identify routing or content changes.

## Notes
- Tests host header manipulation with evil domain values
- Checks for host value reflection in response body and headers
- Runs per-request to test each endpoint
- Can lead to password reset poisoning, cache poisoning, and SSRF

## References
- https://portswigger.net/web-security/host-header
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection`

	ModuleConfirmation = "Confirmed when manipulated Host header value is reflected in response body, Location header, or other response headers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "misconfiguration", "moderate"}
)
