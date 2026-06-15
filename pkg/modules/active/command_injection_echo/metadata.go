package command_injection_echo

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-echo"
	ModuleName  = "OS Command Injection (Results-Based)"
	ModuleShort = "Detects OS command injection by making the shell compute a unique arithmetic value echoed back in the response"
)

var (
	ModuleDesc = `**What it means:** The application passes attacker-controlled input into an OS shell command without sanitization, executing it on the server. Proven by injecting an arithmetic expression the shell computed and returned.

**How it's exploited:** An attacker injects shell metacharacters to run arbitrary commands as the web service account - reading files, harvesting credentials, pivoting internally, and deploying malware for full server compromise. Confirmed across two rounds with fresh markers, so it is exploitable, not reflection.

**Fix:** Avoid invoking the shell on user input; use parameterized OS APIs, and where unavoidable, allow-list values and escape arguments.`

	ModuleConfirmation = "Confirmed when the shell evaluates an injected arithmetic expression and the resulting unique needle appears in the response across two independent rounds while being absent from the unpayloaded baseline"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "command-injection", "injection", "moderate"}
)
