package command_injection_oast

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-oast"
	ModuleName  = "OS Command Injection (Out-of-Band)"
	ModuleShort = "Detects blind OS command injection via out-of-band DNS/HTTP callbacks"
)

var (
	ModuleDesc = `## Description
Detects blind OS command injection that produces no reflected output and no
reliable timing signal, by injecting commands that resolve or fetch a unique,
unguessable out-of-band (OAST) domain — ` + "`nslookup`, `host`, `ping`, `curl`, `wget`" + `.
A correlated interaction with the per-payload subdomain is unforgeable proof that
the injected command executed.

## False-positive defenses
- Each payload targets a unique random subdomain tied to the originating request
  and parameter, so a callback cannot be confused with unrelated traffic.
- The shell metacharacters in the payload (separators / command substitution)
  mean a clean resolution of the exact subdomain requires the command to run,
  rather than the parameter being passed wholesale to an SSRF/DNS sink.

## Notes
- Injects into request parameters (all types) and a small set of commonly
  command-processed headers (User-Agent, Referer, X-Forwarded-For).
- Findings arrive asynchronously via the OAST polling callback; DNS callbacks are
  rated High and HTTP callbacks Critical for command-injection payloads.
- Requires an OAST provider to be configured; otherwise the module is a no-op.
- Complements the in-band (` + "`command-injection-echo`" + `) and time-based
  (` + "`command-injection-timing`, `code-exec`" + `) command-injection modules.

## References
- https://owasp.org/www-community/attacks/Command_Injection
- https://portswigger.net/burp/documentation/collaborator`

	ModuleConfirmation = "Confirmed when an injected command causes the target to resolve or fetch a unique, correlated OAST subdomain"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "command-injection", "oast", "moderate"}
)
