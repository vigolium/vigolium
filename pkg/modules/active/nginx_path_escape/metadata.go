package nginx_path_escape

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nginx-path-escape"
	ModuleName  = "Nginx Path Escape Detection"
	ModuleShort = "Diff-based Nginx path escape detection (alias traversal, encoding bypass, semicolon injection)"
)

var (
	ModuleDesc = `**What it means:** The server appears to mishandle path normalization in a way characteristic of Nginx misconfigurations, letting a crafted URL reach content outside the intended directory or past an access-control rule. This is a Tentative, informational lead from differential response analysis (comparing a baseline request to path-escape payloads such as off-by-slash alias traversal, encoded-dot/encoded-slash and double-encoding bypasses, backslash and overlong-UTF-8 tricks, semicolon and matrix-parameter injection, and double-slash or case-sensitivity ACL bypasses), so a human should confirm it before treating it as an exploitable issue.
**How it's exploited:** An attacker rewrites the request path (for example seg../ to escape a misconfigured alias root, or /..;/ to slip past a location block) so the server serves files or routes it should not, exposing source code, config, or internal endpoints that bypass authentication or access rules.
**Fix:** Correct the Nginx alias/location configuration (avoid off-by-slash alias rules, normalize and reject traversal sequences and semicolon path parameters, and enforce access controls on the resolved path).`

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
