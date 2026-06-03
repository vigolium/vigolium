package nginx_path_escape

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nginx-path-escape"
	ModuleName  = "Nginx Path Escape Detection"
	ModuleShort = "Diff-based Nginx path escape detection (alias traversal, encoding bypass, semicolon injection)"
)

var (
	ModuleDesc = `## Description
Detects Nginx path escape vulnerabilities through differential response analysis,
testing alias traversal, URL encoding bypass, and semicolon injection techniques.

## Notes
- Uses response fingerprint comparison between baseline and test requests
- Tests per-request with multiple escape techniques
- Targets Nginx-specific path handling behaviors

## References
- https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/`

	ModuleConfirmation = "Confirmed when path escape payloads produce different response content or status compared to the baseline, indicating path traversal"
	// ModuleSeverity is Info: this diff-based detector compares response
	// fingerprints between a baseline and path-escape payloads, which is a
	// noisy, false-positive-prone heuristic. Every finding is surfaced as an
	// informational lead for a human to confirm rather than an actionable
	// issue. The per-probe severity remains in the report body for triage.
	// See ScanPerRequest.
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"nginx", "misconfiguration", "moderate"}
)
