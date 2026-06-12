package smart_behavior_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "smart-behavior-detection"
	ModuleName  = "Smart Behavior Detection"
	ModuleShort = "Diff-based injection detection via behavioral analysis"
)

var (
	ModuleDesc = `**What it means:** A parameter shows behavioral signs that its value is parsed as code or query syntax on the server, not treated as inert data. The scanner injected pairs of payloads, a syntax-breaking one (an unbalanced quote/backslash/backtick, a divide-by-zero, a string concatenator, or an ORDER BY function call) and a benign syntax-safe equivalent, and the broken payload changed the response (status code or length) while the safe one did not. That differential is the classic fingerprint of a server-side injection context such as SQL injection, and it indicates the input is reaching an interpreter.

**How it's exploited:** This is an Info-level, low-confidence triage lead, not a confirmed exploit. It tells an attacker (or analyst) exactly which parameter, delimiter, and operator break the back-end syntax, giving a ready starting point to craft a working SQL injection or expression-injection payload that could read or modify data or run commands.

**Fix:** Use parameterized queries or prepared statements and validate or escape untrusted input before it reaches any interpreter.`

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
