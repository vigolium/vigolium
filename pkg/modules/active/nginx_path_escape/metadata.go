package nginx_path_escape

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nginx-path-escape"
	ModuleName  = "Nginx Path Escape Detection"
	ModuleShort = "Diff-based Nginx path escape detection (alias traversal, encoding bypass, semicolon injection)"
)

var (
	ModuleDesc = `**What it means:** The server appears to mishandle path normalization like a misconfigured Nginx, letting a crafted URL reach content outside the intended directory or past an access rule. This Tentative, informational lead comes from differential analysis (alias traversal, encoded-dot/slash, semicolon injection, ACL bypasses); confirm it manually.

**How it's exploited:** An attacker rewrites the path (seg../ to escape an alias root, or /..;/ to slip past a location block) so the server serves files it should not, exposing source or config.

**Fix:** Correct the alias/location configuration, reject traversal sequences and semicolon parameters, and enforce access controls on the resolved path.`

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
