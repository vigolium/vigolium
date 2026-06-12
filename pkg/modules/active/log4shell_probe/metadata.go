package log4shell_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "log4shell-probe"
	ModuleName  = "Log4Shell Probe"
	ModuleShort = "Detects Log4Shell (CVE-2021-44228) via JNDI payload injection with OAST callbacks"
)

var (
	ModuleDesc = `**What it means:** The application uses a vulnerable version of the Apache Log4j logging library affected by Log4Shell (CVE-2021-44228). When user-supplied input reaches a log statement, Log4j evaluates embedded JNDI lookup expressions, letting an attacker make the server fetch and execute attacker-controlled code. This module confirmed the flaw by injecting JNDI payloads into commonly logged HTTP headers (X-Forwarded-For, User-Agent, Referer, Authorization, and others) and request parameters, including lowercase-obfuscated variants to slip past WAF rules, and observing an out-of-band DNS or LDAP callback to the OAST server it controls.

**How it's exploited:** An attacker sends a request containing a JNDI lookup that points the server at a malicious LDAP/RMI endpoint; Log4j resolves it and loads a remote class, achieving unauthenticated remote code execution on the host. This typically leads to full server compromise, data theft, and lateral movement.

**Fix:** Upgrade Log4j to 2.17.1 or later (or remove the JndiLookup class) and patch all transitive dependencies that bundle vulnerable Log4j.`

	ModuleConfirmation = "Confirmed when target server performs outbound DNS or LDAP lookup to OAST callback URL injected via JNDI expression"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"java", "rce", "heavy"}
)
