package ldap_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ldap-injection"
	ModuleName  = "LDAP Injection"
	ModuleShort = "Detects LDAP injection via error-based and boolean-based techniques"
)

var (
	ModuleDesc = `**What it means:** A parameter feeding an LDAP query (username, uid, cn, or filter) is built into the filter without escaping, so attacker input can alter the query structure. Confirmed by injected syntax provoking an LDAP error.

**How it's exploited:** An attacker injects LDAP metacharacters (such as *, )(objectClass=*, or *)(uid=*) to break out of the filter, bypassing authentication or expanding it with wildcards to enumerate directory entries, leaking usernames and group membership.

**Fix:** Escape all special characters in user input before placing it in an LDAP filter (per RFC 4515), and validate the input format.`

	ModuleConfirmation = "Confirmed when injected LDAP filter syntax triggers error messages or produces differential responses indicating filter manipulation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "heavy"}
)
