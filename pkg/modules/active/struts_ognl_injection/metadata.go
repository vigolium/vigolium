package struts_ognl_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "struts-ognl-injection"
	ModuleName  = "Struts OGNL Injection"
	ModuleShort = "Detects Apache Struts OGNL injection via Content-Type and parameter payloads"
)

var (
	ModuleDesc = `**What it means:** Apache Struts evaluates attacker-supplied OGNL expressions as code instead of inert data - the CVE-2017-5638 / S2-045 class, one of the most damaging bugs a Java web app can have.

**How it's exploited:** A benign OGNL math expression injected into the Content-Type header via %{...} syntax appears computed in the response, proving evaluation. An attacker swaps the math for OGNL invoking Java runtime methods, gaining remote command execution.

**Fix:** Upgrade Struts to a patched release, apply the S2-045 mitigations, and never pass user input into OGNL or the ValueStack.`

	ModuleConfirmation = "Confirmed when injected OGNL math expression is evaluated and the computed result appears in the response body or headers"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"java", "rce", "moderate"}
)
