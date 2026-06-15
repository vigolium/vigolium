package reflected_ssti

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "reflected-ssti"
	ModuleName  = "Reflected SSTI"
	ModuleShort = "Detects SSTI via math expression evaluation"
)

var (
	ModuleDesc = `**What it means:** Server-Side Template Injection: user input reaches a template engine (Jinja2, Twig, Freemarker, Velocity, ERB) and is evaluated as code rather than rendered as text - a critical server-side code-evaluation flaw.

**How it's exploited:** The scanner injects a math expression like {{1970*2024}} across many engine delimiters and confirms only when the product (3987280) appears, re-verified against a clean baseline. From arithmetic an attacker escalates to reading server-side variables and, on most engines, full remote code execution.

**Fix:** Never pass user input into template source; render untrusted data only through context-safe variables, and sandbox the engine.`

	ModuleConfirmation = "Confirmed when injected math expressions (e.g., {{7*7}}=49) are evaluated and the computed result appears in the response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "ssti", "moderate"}
)
