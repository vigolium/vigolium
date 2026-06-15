package smart_behavior_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "smart-behavior-detection"
	ModuleName  = "Smart Behavior Detection"
	ModuleShort = "Diff-based injection detection via behavioral analysis"
)

var (
	ModuleDesc = `**What it means:** A parameter shows behavioral signs its value is parsed as code or query syntax, not inert data. The scanner injected a syntax-breaking payload (unbalanced quote, divide-by-zero, ORDER BY call) and a benign equivalent; only the broken one changed the response - the classic fingerprint of a server-side injection context like SQL injection.

**How it's exploited:** This is an Info-level triage lead, not a confirmed exploit. It tells an analyst which parameter breaks the back-end syntax, a starting point for an injection payload.

**Fix:** Use parameterized queries or prepared statements and validate untrusted input before any interpreter.`

	ModuleConfirmation = "Indicated when semantically different payloads produce measurably different response behaviors while equivalent payloads produce identical responses"
	// ModuleSeverity is Info: diff-based behavioral injection detection is an
	// inherently noisy, low-confidence triage heuristic (per-request response
	// volatility, reflection echoes), so every finding is surfaced as an
	// informational lead for a human to confirm rather than an actionable issue.
	// See ScanPerInsertionPoint.
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"behavior-analysis", "injection", "moderate"}
)
