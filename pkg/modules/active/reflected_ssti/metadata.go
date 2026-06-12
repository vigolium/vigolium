package reflected_ssti

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "reflected-ssti"
	ModuleName  = "Reflected SSTI"
	ModuleShort = "Detects SSTI via math expression evaluation"
)

var (
	ModuleDesc = `**What it means:** Server-Side Template Injection was found: user-supplied input reaches a server-side template engine (such as Jinja2, Twig, Freemarker, Velocity, or ERB) and is evaluated as template code rather than rendered as plain text. This is a critical-impact server-side code-evaluation flaw, not a display issue.

**How it's exploited:** The scanner injects a math expression (for example {{1970*2024}}) using delimiters for many engines and confirms the flaw only when the evaluated product (3987280) appears in the response, re-verified against a clean baseline. Because the engine executes attacker-controlled expressions, an attacker can escalate from arithmetic to reading server-side variables and template internals and, on most engines, to full remote code execution and complete server compromise.

**Fix:** Never pass user input into template source; render untrusted data only as data through context-safe variables, and run the template engine sandboxed with a strict allowlist of permitted operations.`

	ModuleConfirmation = "Confirmed when injected math expressions (e.g., {{7*7}}=49) are evaluated and the computed result appears in the response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "ssti", "moderate"}
)
