package ssti_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssti-blind"
	ModuleName  = "Blind Server-Side Template Injection (SSTI)"
	ModuleShort = "Detects blind SSTI via OAST callbacks and time-delay payloads"
)

var (
	ModuleDesc = `**What it means:** User-supplied input reaches a server-side template engine (Jinja2, Twig, Freemarker, ERB, EJS, Pebble) and is evaluated as template code, not data. The response shows no visible difference (a blind variant), but the attacker controls code inside the engine.

**How it's exploited:** Confirmed two ways - a payload running nslookup to an out-of-band host yields a DNS callback (command execution), and paired heavy/trivial loops whose consistent delay flags a time-based signal. An attacker escalates this to remote code execution.

**Fix:** Never pass untrusted input into template source; render user data only through context-escaped variables.`

	ModuleConfirmation = "Confirmed via OAST DNS callback from template evaluation or consistent time-delay differential"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "ssti", "heavy"}
)
