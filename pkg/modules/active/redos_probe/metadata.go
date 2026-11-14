package redos_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "redos-probe"
	ModuleName  = "ReDoS Probe"
	ModuleShort = "Detects regular-expression denial of service by timing growing backtracking inputs against pattern-validated parameters"
)

var (
	ModuleDesc = `**What it means:** A parameter is validated with a regular expression that backtracks catastrophically, so the matching time grows super-linearly with crafted input (ReDoS). Confirmed when growing "aaaa…!" inputs add delay that grows faster than their length across two rounds, while same-length inputs that match stay fast.

**How it's exploited:** An attacker sends a few short crafted values that each occupy a worker for seconds or longer, exhausting the server's capacity and denying service to every user.

**Fix:** Rewrite the pattern without nested or overlapping quantifiers, cap input length before matching, or use a linear-time regex engine (RE2).`

	ModuleConfirmation = "Confirmed when the delay added by \"aaaa…!\" inputs over a same-length matching control grows super-linearly with the input length (16/32/64 characters) in two independent rounds"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	// "risk:high" is modules.TagRiskHigh (a literal here: pkg/modules imports
	// this package). A vulnerable pattern pins a server worker per probe, so a
	// broad selection only runs the module at --intensity deep or with
	// --allow-risky-payloads; -m still runs it explicitly.
	ModuleTags = []string{"dos", "redos", "intrusive", "risk:high"}
)
