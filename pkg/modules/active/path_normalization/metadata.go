package path_normalization

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "path-normalization"
	ModuleName  = "Path Normalization"
	ModuleShort = "Detects path normalization vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** The reverse proxy and backend normalize traversal sequences (..%2f, ..;/, encoded dots) differently, so a crafted path reaches a resource the clean URL does not serve, bypassing path-based access controls or escaping a static handler's root.

**How it's exploited:** An attacker sends an over-encoded or matrix-parameter path so the front-end routes it to a permitted location while the backend resolves a restricted target, reaching endpoints past auth or reading files above the root like /etc/passwd or .env.

**Fix:** Normalize paths identically at every tier before routing and authorization, reject ambiguous encodings, and enforce a strict resolved-path boundary.`

	ModuleConfirmation = "Confirmed either when an over-traversed path is rejected (HTTP 400) while the backed-off, traversal-bearing path reproducibly reaches a 2xx text resource that the clean URL cannot reach (access unlocked) or that differs substantially from the clean baseline (and is not the root/non-existent catch-all shell), or when a matrix-parameter/encoded-slash shell reproducibly reads a known file (or surfaces a directory/bucket listing) off the static root, with baseline-subtracted markers surviving a wildcard and decoy-filename negative"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "lfi", "traversal", "moderate"}
)
