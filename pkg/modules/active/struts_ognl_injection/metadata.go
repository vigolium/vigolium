package struts_ognl_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "struts-ognl-injection"
	ModuleName  = "Struts OGNL Injection"
	ModuleShort = "Detects Apache Struts OGNL injection via Content-Type and parameter payloads"
)

var (
	ModuleDesc = `**What it means:** The application runs on Apache Struts and evaluates attacker-supplied OGNL (Object-Graph Navigation Language) expressions instead of treating them as inert data. This is a server-side code execution flaw (the CVE-2017-5638 / S2-045 class of bug) and one of the most damaging vulnerabilities a Java web app can have.

**How it's exploited:** The scanner injects a benign OGNL math expression (41273 multiplied by 39127) into the Content-Type header and into request parameters using the %{...} and ${...} syntax; when the precomputed product appears in the response, the server provably evaluated the expression. A real attacker swaps the math for OGNL that invokes Java runtime methods, achieving full remote command execution as the web server user, which typically leads to complete server compromise and lateral movement into the internal network.

**Fix:** Upgrade Apache Struts to a patched release and apply the official S2-045 / CVE-2017-5638 mitigations, and never pass user-controlled input into OGNL or the Struts ValueStack.`

	ModuleConfirmation = "Confirmed when injected OGNL math expression is evaluated and the computed result appears in the response body or headers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"java", "rce", "moderate"}
)
