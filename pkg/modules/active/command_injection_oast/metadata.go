package command_injection_oast

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-oast"
	ModuleName  = "OS Command Injection (Out-of-Band)"
	ModuleShort = "Detects blind OS command injection via out-of-band DNS/HTTP callbacks"
)

var (
	ModuleDesc = `**What it means:** The application passes attacker-controlled input into an OS shell command. This blind variant returns no output, so it is confirmed out-of-band: an injected command makes the server contact a unique OAST domain only the scanner could have planted.

**How it's exploited:** An attacker appends shell commands like nslookup or curl to a parameter or header (User-Agent, X-Forwarded-For) fed into a shell. The callback proves execution, enabling file reads, pivoting, or host takeover. DNS is High, an HTTP fetch Critical.

**Fix:** Never pass user input into shell commands; use parameterized library calls and allowlist unavoidable arguments.`

	ModuleConfirmation = "Confirmed when an injected command causes the target to resolve or fetch a unique, correlated OAST subdomain"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "command-injection", "oast", "moderate"}
)
