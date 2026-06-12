package command_injection_oast

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-oast"
	ModuleName  = "OS Command Injection (Out-of-Band)"
	ModuleShort = "Detects blind OS command injection via out-of-band DNS/HTTP callbacks"
)

var (
	ModuleDesc = `**What it means:** The application passes attacker-controlled input into an operating-system shell command without proper sanitisation, allowing arbitrary commands to run on the server. This blind variant produces no visible response, so it is confirmed out-of-band: an injected command makes the server resolve or fetch a unique, unguessable OAST domain that only the scanner could have planted, which is unforgeable proof the command executed.

**How it's exploited:** An attacker appends shell metacharacters and commands such as nslookup, ping, curl, or wget to a request parameter, or to a header like User-Agent, Referer, or X-Forwarded-For that downstream tooling feeds into a shell. The correlated callback proves code execution; from there an attacker can read files, install backdoors, pivot into the internal network, or fully take over the host. A DNS-only callback is reported as High and an HTTP fetch callback as Critical.

**Fix:** Never pass user input into shell commands. Use parameterised library calls or safe APIs instead of shell strings, and strictly allowlist any unavoidable arguments.`

	ModuleConfirmation = "Confirmed when an injected command causes the target to resolve or fetch a unique, correlated OAST subdomain"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "command-injection", "oast", "moderate"}
)
