package command_injection_echo

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-echo"
	ModuleName  = "OS Command Injection (Results-Based)"
	ModuleShort = "Detects OS command injection by making the shell compute a unique arithmetic value echoed back in the response"
)

var (
	ModuleDesc = `## Description
Detects OS command injection in-band, with deterministic proof of execution. The
scanner injects a command that asks the shell to evaluate an arithmetic
expression (` + "`echo <TAG>$((A+B))<TAG>`" + `) where the operands are large random
numbers and the result is wrapped in two unique random delimiters. A reflection
of the literal payload yields the un-evaluated ` + "`$((A+B))`" + ` text; only genuine
command execution yields the computed sum bracketed by the delimiters.

## False-positive defenses (multiple independent layers)
- **Very-unique markers** — large random operands and 14-char random delimiters
  make the expected needle (delimiter + computed sum + delimiter) effectively
  impossible to occur by coincidence in normal page content.
- **Baseline comparison** — the same request is also sent WITHOUT the payload and
  the needle must be ABSENT from that clean response, proving the match is caused
  by the injected payload and is not pre-existing page content.
- **Two independent rounds** — the working breakout context is re-confirmed with a
  brand-new marker (fresh operands and delimiters); both rounds must match, so a
  cached or coincidental hit cannot survive.

## Notes
- Tries multiple shell breakout contexts (separators, quote breakouts, command
  substitution) and arithmetic techniques (` + "`$((…))`, `expr`" + `, and interpreter
  ` + "`print()`" + ` for eval-style sinks).
- Payloads are raw shell strings; the insertion point URL-encodes them and the
  target decodes them before the sink, so metacharacters arrive intact.
- Complements the time-based (` + "`code-exec`, `command-injection-timing`" + `) and
  out-of-band (` + "`command-injection-oast`" + `) command-injection modules.

## References
- https://owasp.org/www-community/attacks/Command_Injection
- https://github.com/commixproject/commix`

	ModuleConfirmation = "Confirmed when the shell evaluates an injected arithmetic expression and the resulting unique needle appears in the response across two independent rounds while being absent from the unpayloaded baseline"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "command-injection", "injection", "moderate"}
)
