package code_exec

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "code-exec"
	ModuleName  = "Code Execution (RCE)"
	ModuleShort = "Detects OS command injection via time-based blind"
)

var (
	ModuleDesc = `**What it means:** A request parameter appears to be passed into an operating-system shell command without proper sanitization, allowing attacker-supplied input to be executed as part of that command. This is a command-injection (remote code execution) weakness. The finding is raised as a time-based blind signal: an injected delay payload reproducibly slowed the response, so it should be treated as suspected and manually verified rather than as a proven OS-command execution.

**How it's exploited:** An attacker injects shell metacharacters and commands (using bash, cmd, PowerShell, or language-specific syntax) into the vulnerable parameter; here the scanner made the server run a 10-second sleep, ping, or timeout and measured the delay against a fast baseline across multiple rounds. Real exploitation lets the attacker run arbitrary commands to read files, steal credentials, pivot through the internal network, and fully compromise the host.

**Fix:** Never pass user input to a shell; use parameterized APIs or strict allow-list validation and avoid invoking OS commands with untrusted data.`

	ModuleConfirmation = "Confirmed when injected sleep/delay commands cause measurable response time increase matching the specified delay"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "injection", "heavy"}
)
