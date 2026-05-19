package struts_ognl_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "struts-ognl-injection"
	ModuleName  = "Struts OGNL Injection"
	ModuleShort = "Detects Apache Struts OGNL injection via Content-Type and parameter payloads"
)

var (
	ModuleDesc = `## Description
Detects Apache Struts OGNL injection vulnerabilities by injecting OGNL math expressions
into the Content-Type header (CVE-2017-5638 style) and into request parameters. Uses safe
arithmetic-based detection to confirm expression evaluation without executing commands.

## Notes
- Tests Content-Type header injection for CVE-2017-5638 variants
- Tests parameter-level OGNL expression injection (${} and %{} syntax)
- Uses math expressions (multiplication) to confirm evaluation
- Deduplication via DiskSet (per-request) and RHM (per-insertion-point)

## References
- https://nvd.nist.gov/vuln/detail/CVE-2017-5638
- https://cwiki.apache.org/confluence/display/WW/S2-045
- https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection`

	ModuleConfirmation = "Confirmed when injected OGNL math expression is evaluated and the computed result appears in the response body or headers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"java", "rce", "moderate"}
)
