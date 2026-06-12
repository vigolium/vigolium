package ssti_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssti-blind"
	ModuleName  = "Blind Server-Side Template Injection (SSTI)"
	ModuleShort = "Detects blind SSTI via OAST callbacks and time-delay payloads"
)

var (
	ModuleDesc = `**What it means:** User-supplied input reaches a server-side template engine (Jinja2, Twig, Mako, ERB, Freemarker, EJS, or Pebble) and is evaluated as template code rather than treated as plain data. Because the response shows no visible difference, this is a blind variant, but the underlying flaw is the same: the attacker controls code that runs inside the engine.

**How it's exploited:** The scanner confirms injection two ways. It sends template payloads that shell out to nslookup against a unique out-of-band host; a received DNS callback proves command execution and is reported with Firm confidence. It also sends paired heavy-loop and trivial-loop expressions and times them across interleaved repeated probes; a consistent multi-second delay only on the heavy payload is reported as a Suspect time-delay signal. A real attacker escalates template evaluation to full remote code execution and takes over the server.

**Fix:** Never pass untrusted input into template source; render user data only through context-escaped variables in a sandboxed engine, or strictly validate and reject template metacharacters.`

	ModuleConfirmation = "Confirmed via OAST DNS callback from template evaluation or consistent time-delay differential"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "ssti", "heavy"}
)
