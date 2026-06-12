package input_behavior_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "input-behavior-probe"
	ModuleName  = "Input Behavior Probe"
	ModuleShort = "Detects behavior changes from header, path, debug param, and char probing"
)

var (
	ModuleDesc = `**What it means:** An input probe made the application respond differently from its normal baseline: injecting proxy/host headers (X-Forwarded-Host, X-Original-URL, Host), traversal and encoding tricks in path segments, debug/admin parameters (debug=true, admin=1), special fuzz characters, or a polyglot payload changed the response's HTML tag structure or status code (for example 403 to 200, or 200 to 500). This is an informational triage lead, not a confirmed vulnerability: it flags an input the app handles inconsistently, which often sits next to a real flaw such as path traversal, an auth bypass, a hidden debug mode, request smuggling, or injection.

**How it's exploited:** An attacker treats the diverging input as a starting point and pursues it manually. A 403-to-200 transition can mean an access-control bypass, a header that alters the page can mean host-header or routing abuse, and a 500 or structural break can expose a parser or injection weakness.

**Fix:** Validate and canonicalize all inputs, ignore untrusted proxy/host headers, disable debug parameters, and remediate the underlying issue the probe surfaced.`

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
