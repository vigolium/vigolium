package server_only_boundary_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-only-boundary-audit"
	ModuleName  = "Server-Only Boundary Audit"
	ModuleShort = "Detects server-side modules leaked into client component bundles"
)

var (
	ModuleDesc = `**What it means:** A Next.js client bundle contains two server-oriented import/URL patterns, or one substantive credential-shaped database URI. Import strings can survive dead code and do not prove executable server logic.

**How it's exploited:** Real impact requires useful internal detail, runtime reachability, or a live credential. The module performs no call-graph or provider validation, so results remain candidates; obvious placeholder URIs are suppressed.

**Fix:** Wrap server-only modules with the server-only package and keep secrets and internal URLs out of client code.`

	ModuleConfirmation = "Candidate after two server-oriented signals or one non-placeholder credentialed database URI; runtime reachability and credential validity remain unconfirmed"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "info-disclosure", "light"}
)
