package ldap_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ldap-injection"
	ModuleName  = "LDAP Injection"
	ModuleShort = "Detects LDAP injection via error-based and boolean-based techniques"
)

var (
	ModuleDesc = `**What it means:** A parameter that feeds an LDAP directory query (such as username, uid, cn, or a search filter) is built into the filter without proper escaping, so attacker-supplied input can alter the structure of the LDAP query. This module confirmed this by injecting malformed LDAP filter syntax that either provoked an LDAP error message absent from the original response, or by sending a wildcard probe whose response diverged substantially from both the original page and a no-match control.

**How it's exploited:** An attacker injects LDAP metacharacters and filter fragments (for example *, )(objectClass=*, or *)(uid=*) to break out of the intended filter. This lets them bypass authentication, enumerate directory entries they should not see, or return unrelated records by expanding the filter with wildcards and OR clauses, leaking usernames, group membership, and other directory data.

**Fix:** Escape all special characters in user input before placing it in an LDAP filter (per RFC 4515) using a vetted encoding routine, and validate or allowlist the expected input format.`

	ModuleConfirmation = "Confirmed when injected LDAP filter syntax triggers error messages or produces differential responses indicating filter manipulation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "heavy"}
)
