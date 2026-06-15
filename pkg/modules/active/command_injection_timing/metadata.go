package command_injection_timing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-timing"
	ModuleName  = "OS Command Injection (Time-Based)"
	ModuleShort = "Detects blind OS command injection by confirming the response delay scales with the injected sleep duration"
)

var (
	ModuleDesc = `**What it means:** The application appears to pass attacker-controlled input into an OS shell command. The scanner probed this blind, no-output case by injecting sleep/ping delays and watching response time scale with the requested delay.

**How it's exploited:** An attacker injects shell commands to run code as the web app user, reading files, stealing credentials, and controlling the host. Output is exfiltrated via timing or DNS callbacks.

**Fix:** Never build shell strings from user input; pass arguments as a fixed array without a shell. Timing-only, so reported Tentative - corroborate with the echo or OAST modules.`

	ModuleConfirmation = "Suspected when injected sleep commands cause a response delay that scales with the requested duration across multiple independent rounds, above an adaptive per-target threshold; timing-only so reported as Tentative"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"rce", "command-injection", "injection", "heavy"}
)
