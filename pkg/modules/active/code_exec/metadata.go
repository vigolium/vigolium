package code_exec

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "code-exec"
	ModuleName  = "Code Execution (RCE)"
	ModuleShort = "Detects OS command injection via time-based blind"
)

var (
	ModuleDesc = `**What it means:** A request parameter is passed into an OS shell command without sanitization, letting attacker input execute as part of it - a command-injection (RCE) weakness. Raised as a time-based blind signal: an injected delay payload reproducibly slowed the response, so verify manually.

**How it's exploited:** An attacker injects shell metacharacters and commands; here the scanner made the server run a 10-second sleep/ping/timeout against a fast baseline. Real exploitation runs arbitrary commands to take over the host.

**Fix:** Never pass user input to a shell; use parameterized APIs or strict allow-list validation, not OS commands with untrusted data.`

	ModuleConfirmation = "Confirmed when injected sleep/delay commands cause measurable response time increase matching the specified delay"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "injection", "heavy"}
)
