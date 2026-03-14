package log4shell_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "log4shell-probe"
	ModuleName  = "Log4Shell Probe"
	ModuleShort = "Detects Log4Shell (CVE-2021-44228) via JNDI payload injection with OAST callbacks"
)

var (
	ModuleDesc = `## Description
Detects Log4Shell (CVE-2021-44228) and related Log4j JNDI injection vulnerabilities by
injecting JNDI lookup payloads into HTTP headers and request parameters. Uses OAST
(Out-of-band Application Security Testing) callbacks to confirm exploitation.

## Notes
- Requires an interactsh server (configured via oast settings)
- Injects JNDI payloads into common HTTP headers (X-Forwarded-For, User-Agent, etc.)
- Tests multiple JNDI obfuscation patterns to bypass WAF rules
- Injects JNDI payloads into request parameters via insertion points
- Findings arrive asynchronously via the OAST polling callback
- Deduplication via DiskSet (per-request) and RHM (per-insertion-point)

## References
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://logging.apache.org/log4j/2.x/security.html
- https://www.lunasec.io/docs/blog/log4j-zero-day/`

	ModuleConfirmation = "Confirmed when target server performs outbound DNS or LDAP lookup to OAST callback URL injected via JNDI expression"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"java", "rce", "heavy"}
)
