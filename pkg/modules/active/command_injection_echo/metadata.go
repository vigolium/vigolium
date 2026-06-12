package command_injection_echo

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-echo"
	ModuleName  = "OS Command Injection (Results-Based)"
	ModuleShort = "Detects OS command injection by making the shell compute a unique arithmetic value echoed back in the response"
)

var (
	ModuleDesc = `**What it means:** The application passes attacker-controlled input into an operating-system shell command without proper sanitization, so the attacker's input is executed as commands on the server. This was proven, not guessed: the scanner injected an arithmetic expression and the server's shell computed and returned the unique result, confirming real command execution.

**How it's exploited:** An attacker injects shell metacharacters (such as separators, quote breakouts, or command substitution) into the affected parameter to run arbitrary commands as the web service account. This typically leads to full server compromise, including reading or modifying files, harvesting credentials, pivoting into the internal network, and deploying malware. The scanner confirmed execution across two independent rounds with fresh random markers, each absent from the clean baseline, so this is a high-confidence, exploitable finding rather than mere reflection.

**Fix:** Avoid invoking the shell on user input; use parameterized OS APIs or safe library calls, and if a command must be built, strictly allow-list permitted values and escape arguments.`

	ModuleConfirmation = "Confirmed when the shell evaluates an injected arithmetic expression and the resulting unique needle appears in the response across two independent rounds while being absent from the unpayloaded baseline"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "command-injection", "injection", "moderate"}
)
