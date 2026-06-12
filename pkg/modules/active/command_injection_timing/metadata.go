package command_injection_timing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-timing"
	ModuleName  = "OS Command Injection (Time-Based)"
	ModuleShort = "Detects blind OS command injection by confirming the response delay scales with the injected sleep duration"
)

var (
	ModuleDesc = `**What it means:** The application appears to pass attacker-controlled input into an operating-system shell command, with no command output reflected back. The scanner confirmed this blind case by injecting time-delay commands (sleep/ping) and observing the response time grow in proportion to the requested delay. If genuine, this is OS command injection, letting an attacker run arbitrary commands on the server.

**How it's exploited:** An attacker injects shell commands into the affected parameter to run code as the web application's user, allowing them to read or modify files, steal credentials and secrets, pivot to internal systems, and take full control of the host. Since no output is returned, data is exfiltrated through timing, DNS, or HTTP callbacks.

**Fix:** Never build shell command strings from user input; use APIs that pass arguments as a fixed array without invoking a shell, and strictly allowlist any user-supplied values.

Note: this timing-only oracle is sensitive to network conditions, so it is reported as Tentative; corroborate with the in-band (command-injection-echo) or out-of-band (command-injection-oast) modules where possible.`

	ModuleConfirmation = "Suspected when injected sleep commands cause a response delay that scales with the requested duration across multiple independent rounds, above an adaptive per-target threshold; timing-only so reported as Tentative"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"rce", "command-injection", "injection", "heavy"}
)
