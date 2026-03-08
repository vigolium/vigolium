package nosqli_operator_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-nosqli-operator-injection"
	ModuleName  = "NoSQL Operator Injection"
	ModuleShort = "Detects MongoDB operator injection ($ne, $gt, $regex, $where) for auth bypass and data exfiltration"
)

var (
	ModuleDesc = `## Description
Tests for NoSQL injection by injecting MongoDB query operators ($ne, $gt, $regex,
$where) and detecting authentication bypass, data exfiltration, and behavioral
changes. Complements nosqli_error_based by focusing on operator-level injection
rather than error messages.

## Notes
- Payload selection adapts to insertion point type (JSON, URL, body)
- Four detection modes: auth bypass, size increase, boolean differential, time delay
- Skips when NoSQL error patterns are detected (deferred to nosqli_error_based)
- Deduplicates by request hash manager

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection`

	ModuleConfirmation = "Confirmed when NoSQL operator injection causes authentication bypass, data exfiltration, or measurable behavioral change"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"injection", "sqli", "moderate"}
)
