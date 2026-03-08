package insecure_deserialization

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-insecure-deserialization"
	ModuleName  = "Insecure Deserialization"
	ModuleShort = "Detects insecure deserialization via error-based detection"
)

var (
	ModuleDesc = `## Description
Detects insecure deserialization vulnerabilities by injecting serialized object payloads
and analyzing responses for deserialization error messages across multiple frameworks.

## Notes
- Tests for Java, PHP, Python, Ruby, and .NET deserialization patterns
- Uses error-based detection to identify deserialization endpoints
- Analyzes response bodies for framework-specific error messages
- OWASP Top 10 2021: A08

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests
- https://portswigger.net/web-security/deserialization`

	ModuleConfirmation = "Confirmed when injected serialized payloads trigger deserialization error messages in the response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"deserialization", "rce", "moderate"}
)
