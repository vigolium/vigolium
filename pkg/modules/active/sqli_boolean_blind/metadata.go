package sqli_boolean_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-sqli-boolean-blind"
	ModuleName  = "Blind SQL Injection (Boolean-Based)"
	ModuleShort = "Detects boolean-based blind SQL injection vulnerabilities"
)

var (
	ModuleDesc = `## Description
Tests for boolean-based blind SQL injection by sending paired TRUE/FALSE payloads and comparing
response differentials. Uses triple-verification to minimize false positives: TRUE and FALSE
payloads must produce consistently different responses across multiple requests.

## Notes
- Sends TRUE and FALSE payload pairs to each injection point
- Compares responses using status code, body length differential, and content hash
- Triple-verification: confirms TRUE/FALSE differential is consistent across retries
- Tests string context, numeric context, and WAF bypass payloads
- Uses NoRedirects to capture TRUE/FALSE differential before redirect

## References
- https://owasp.org/www-community/attacks/Blind_SQL_Injection
- https://portswigger.net/web-security/sql-injection/blind`

	ModuleConfirmation = "Confirmed when TRUE payloads consistently produce different responses from FALSE payloads across multiple verification requests"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"injection", "sqli", "heavy"}
)
