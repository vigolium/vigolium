package crlf_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "crlf-injection"
	ModuleName  = "CRLF Injection"
	ModuleShort = "Detects CRLF injection"
)

var (
	ModuleDesc = `## Description
Detects CRLF injection vulnerabilities in HTTP headers by injecting carriage return and
line feed characters and checking if they appear in response headers.

## Notes
- Tests URL parameters for header injection via CRLF sequences
- Can lead to HTTP response splitting and header injection attacks

## References
- https://owasp.org/www-community/vulnerabilities/CRLF_Injection`

	ModuleConfirmation = "Confirmed when injected CRLF sequences appear in HTTP response headers, indicating header injection"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"crlf", "injection", "moderate"}
)
