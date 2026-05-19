package ldap_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ldap-injection"
	ModuleName  = "LDAP Injection"
	ModuleShort = "Detects LDAP injection via error-based and boolean-based techniques"
)

var (
	ModuleDesc = `## Description
Detects LDAP injection vulnerabilities by injecting malformed LDAP filter expressions into
parameters that are likely used in LDAP queries (e.g., username, search, filter). Uses both
error-based detection (checking for LDAP error messages in responses) and boolean-based
detection (comparing responses with wildcard vs. baseline).

## Notes
- Only tests parameters whose name suggests LDAP usage (username, uid, cn, filter, etc.)
- Checks for LDAP error messages that were not present in the baseline response
- Performs boolean-based differential analysis with wildcard injection
- Deduplication via RHM to avoid redundant requests

## References
- https://owasp.org/www-community/attacks/LDAP_Injection
- https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when injected LDAP filter syntax triggers error messages or produces differential responses indicating filter manipulation"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "heavy"}
)
