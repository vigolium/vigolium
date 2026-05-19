package code_exec

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "code-exec"
	ModuleName  = "Code Execution (RCE)"
	ModuleShort = "Detects OS command injection via time-based blind"
)

var (
	ModuleDesc = `## Description
Detects OS Command Injection vulnerabilities using time-based blind detection. Injects
sleep/delay commands and measures response time differences to confirm execution.

## Notes
- Uses time-based blind technique to avoid false positives
- Tests multiple shell syntaxes (bash, cmd, PowerShell)

## References
- https://owasp.org/www-community/attacks/Command_Injection
- https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1571571c`

	ModuleConfirmation = "Confirmed when injected sleep/delay commands cause measurable response time increase matching the specified delay"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "injection", "heavy"}
)
