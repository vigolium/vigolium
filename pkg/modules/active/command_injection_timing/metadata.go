package command_injection_timing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-timing"
	ModuleName  = "OS Command Injection (Time-Based)"
	ModuleShort = "Detects blind OS command injection by confirming the response delay scales with the injected sleep duration"
)

var (
	ModuleDesc = `## Description
Detects blind OS command injection where the command produces no output, using a
delay-scaling oracle. For each insertion point the scanner first models the
target's normal latency to derive an adaptive delay threshold, then injects
` + "`sleep`/`ping`" + ` commands at two different durations and confirms the observed
delay tracks the requested value.

## False-positive defenses
- **Adaptive per-target threshold** — derived from the baseline mean and standard
  deviation, so jittery/slow hosts raise the bar (or are skipped) instead of
  triggering on ambient latency.
- **Delay scaling** — the decisive check: a high-sleep and a low-sleep payload
  must differ by ~the requested amount. Random server slowness or a fixed
  timeout/retry path produces a delay that does NOT grow with the sleep argument
  and is rejected.
- **Multiple rounds** — the full scaling check must pass on every one of several
  independent rounds, so a transient network spike (GC pause, scheduler stall,
  packet retransmit) on a single probe cannot, on its own, produce a finding.

## Confidence
- Reported as **Tentative**. Even with delay scaling and multi-round
  confirmation, a purely timing-based oracle remains the most sensitive to
  network conditions, so findings are flagged for corroboration rather than
  asserted outright.
- Prefer the in-band (` + "`command-injection-echo`" + `) and out-of-band
  (` + "`command-injection-oast`" + `) modules, which prove execution deterministically;
  this module is a fallback for fully blind sinks with no reflected output and no
  callback path.

## References
- https://owasp.org/www-community/attacks/Command_Injection
- https://github.com/commixproject/commix`

	ModuleConfirmation = "Suspected when injected sleep commands cause a response delay that scales with the requested duration across multiple independent rounds, above an adaptive per-target threshold; timing-only so reported as Tentative"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"rce", "command-injection", "injection", "heavy"}
)
