package input_behavior_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "input-behavior-probe"
	ModuleName  = "Input Behavior Probe"
	ModuleShort = "Detects behavior changes from header, path, debug param, and char probing"
)

var (
	ModuleDesc = `**What it means:** An input probe made the application respond differently from its baseline: proxy/host headers (X-Forwarded-Host, X-Original-URL), path traversal, debug/admin parameters (debug=true, admin=1), or a polyglot changed the HTML structure or status code (for example 403 to 200). An informational triage lead, not a confirmed flaw.

**How it's exploited:** An attacker pursues the diverging input. A 403-to-200 transition can signal an access-control bypass, a header altering the page can signal host-header or routing abuse, and a 500 can expose injection.

**Fix:** Validate and canonicalize inputs, ignore untrusted proxy/host headers, disable debug parameters, and fix the underlying issue.`

	ModuleConfirmation = "Indicated when probed requests cause structural changes in the response HTML tag tree or notable status code transitions compared to the baseline"
	// ModuleSeverity is Info: this diff-based behavior-probing module compares
	// HTML tag structure and status codes against a baseline, which is an
	// inherently noisy, low-confidence triage signal. Findings do not set a
	// per-result severity, so they inherit this declared Info severity (see
	// buildProbeResult in detect.go) and are surfaced as informational leads.
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"injection", "probe", "moderate"}
)
