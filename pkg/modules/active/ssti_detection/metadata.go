package ssti_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssti-detection"
	ModuleName  = "SSTI Detection"
	ModuleShort = "Diff-based SSTI detection via error responses"
)

var (
	ModuleDesc = `**What it means:** This is a blind, differential lead suggesting a parameter value may be evaluated by a server-side template engine (Jinja2, Twig, Freemarker, Velocity, SpEL, ERB, EJS and others). The scanner sends template-breaking expressions and reordered equivalents and observes that they produce consistently different responses than the original value, which is a hallmark of server-side template processing rather than plain string handling. Because it relies on response differences and error pages, it is reported at Info severity as a candidate for a human to confirm, not a proven vulnerability.

**How it's exploited:** If a real Server-Side Template Injection exists, an attacker submits template syntax that the engine evaluates, allowing them to read server-side variables and, with many engines, escalate to arbitrary code execution and full server compromise. The detected engine narrows which exploitation payloads to try.

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
