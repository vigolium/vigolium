package log4shell_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "log4shell-probe"
	ModuleName  = "Log4Shell Probe"
	ModuleShort = "Detects Log4Shell (CVE-2021-44228) via JNDI payload injection with OAST callbacks"
)

var (
	ModuleDesc = `**What it means:** The app uses an Apache Log4j version vulnerable to Log4Shell (CVE-2021-44228), where user input reaching a log statement triggers JNDI lookups that fetch and run remote code. Confirmed by injecting JNDI payloads into logged headers and seeing an out-of-band DNS/LDAP callback to the OAST server.

**How it's exploited:** An attacker sends a JNDI lookup pointing the server at a malicious LDAP/RMI endpoint; Log4j resolves it and loads a remote class, achieving unauthenticated RCE and full server compromise.

**Fix:** Upgrade Log4j to 2.17.1 or later (or remove the JndiLookup class) and patch all dependencies bundling vulnerable Log4j.`

	ModuleConfirmation = "Confirmed when target server performs outbound DNS or LDAP lookup to OAST callback URL injected via JNDI expression"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"java", "rce", "heavy"}
)
