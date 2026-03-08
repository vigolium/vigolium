package input_behavior_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-input-behavior-probe"
	ModuleName  = "Input Behavior Probe"
	ModuleShort = "Detects behavior changes from header, path, debug param, and char probing"
)

var (
	ModuleDesc = `## Description
Comprehensive behavior probing module that detects anomalous responses by
comparing HTML tag structure and status codes against a baseline. Operates
at both request scope and insertion-point scope.

## Probe Types
1. **Header probing** (per-request): Injects values into known security-relevant
   headers (X-Forwarded-Host, X-Original-URL, etc.) and weird header names.
2. **Path manipulation** (per-request): Applies prefix/postfix path traversal
   and encoding tricks to each URL path segment.
3. **Debug parameter injection** (per-request): Appends debug/admin parameters
   (debug=true, admin=1, etc.) to detect hidden debug modes.
4. **Polyglot fuzz** (per-insertion-point): Injects a polyglot payload to detect
   HTML tag structure changes (original behavior).
5. **Param char fuzzing** (per-insertion-point): Appends special characters to
   parameter values to detect parser-level behavior differences.

## Notes
- Compares HTML tag counts and status codes between baseline and probed responses
- Low confidence; useful as a triage signal for manual investigation
- Per-request probes are deduped by host+path; per-IP probes are deduped by request hash

## References
- https://owasp.org/www-community/Fuzzing
- https://portswigger.net/research/backslash-powered-scanning`

	ModuleConfirmation = "Indicated when probed requests cause structural changes in the response HTML tag tree or notable status code transitions compared to the baseline"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"injection", "probe", "moderate"}
)
