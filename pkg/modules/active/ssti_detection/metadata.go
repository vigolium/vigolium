package ssti_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssti-detection"
	ModuleName  = "SSTI Detection"
	ModuleShort = "Diff-based SSTI detection via error responses"
)

var (
	ModuleDesc = `**What it means:** A blind differential lead that a parameter may be evaluated by a server-side template engine (Jinja2, Twig, Freemarker, SpEL, ERB, EJS). Template-breaking expressions produce consistently different responses than the original value. Reported at Info for human confirmation, not a proven bug.

**How it's exploited:** If real SSTI exists, an attacker submits template syntax the engine evaluates to read server-side variables and, with many engines, escalate to remote code execution and full server compromise.

**Fix:** Never place untrusted input into template source; pass user data only as bound, escaped variables to the rendering context.`

	ModuleConfirmation = "Confirmed when valid template expressions produce different responses than syntactically invalid ones, indicating server-side evaluation"
	// ModuleSeverity is Info: this diff-based, error-response heuristic is
	// false-positive-prone (reflection echoes, per-request volatility, generic
	// error pages), so every finding is surfaced as an informational lead for a
	// human to confirm rather than an actionable issue. See ScanPerInsertionPoint.
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Certain
	ModuleTags       = []string{"injection", "ssti", "moderate"}
)
