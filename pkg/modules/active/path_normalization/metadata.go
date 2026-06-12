package path_normalization

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "path-normalization"
	ModuleName  = "Path Normalization"
	ModuleShort = "Detects path normalization vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** The reverse proxy or framework and the backend disagree on how to normalize a path containing traversal sequences (such as ..%2f, ..;/, or encoded dots). The scanner confirmed a crafted, traversal-bearing path reaches a resource the clean URL does not serve, so path-based access controls and routing can be bypassed. In the static-file case, the request escapes a static handler's root and discloses on-disk files.

**How it's exploited:** An attacker sends an over-encoded or matrix-parameter path so the front-end routes it to a permitted location while the backend (or a static resolver like Node send / serve-static) resolves it to a different, restricted target. This can bypass authentication or proxy ACLs to reach protected endpoints, or read files above the static root such as /etc/passwd, app-root package.json or .env (leaking secrets). A confirmed file read is reported as Critical.

**Fix:** Normalize paths identically at every tier before routing and authorization, reject ambiguous encodings and traversal segments, and enforce a strict resolved-path boundary check on the static root.`

	ModuleConfirmation = "Confirmed either when an over-traversed path is rejected (HTTP 400) while the backed-off, traversal-bearing path reproducibly reaches a 2xx text resource that the clean URL cannot reach (access unlocked) or that differs substantially from the clean baseline (and is not the root/non-existent catch-all shell), or when a matrix-parameter/encoded-slash shell reproducibly reads a known file (or surfaces a directory/bucket listing) off the static root, with baseline-subtracted markers surviving a wildcard and decoy-filename negative"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "lfi", "traversal", "moderate"}
)
