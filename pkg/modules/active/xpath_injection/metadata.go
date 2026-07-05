package xpath_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xpath-injection"
	ModuleName  = "XPath Injection"
	ModuleShort = "Detects XPath/XQuery injection via engine error signatures and a boolean oracle"
)

var (
	ModuleDesc = `**What it means:** A parameter is placed unsanitized into an XPath or XQuery expression (often against an XML datastore or for XML-based authentication), letting an attacker alter the query's logic.

**How it's exploited:** Injecting ' or '1'='1 bypasses XML-based login or returns every node; count()/position() and boolean blind techniques then extract the whole document node by node. Broken syntax also leaks XPath engine errors.

**Fix:** Use parameterized XPath (precompiled expressions with variable binding), validate/allowlist input, and never build XPath by string concatenation.`

	ModuleConfirmation = "Confirmed when a syntax-breaking payload leaks an XPath engine error absent from the baseline (re-verified with a benign control), or when two independent always-true payloads agree, two always-false payloads agree, and the true and false responses differ"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xpath", "moderate"}
)
