package server_action_auth

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-auth"
	ModuleName  = "Server Action Auth Check"
	ModuleShort = "Detects Next.js Server Actions missing authorization checks"
)

var (
	ModuleDesc = `**What it means:** A source-like JS/TS file contains a server directive and mutation syntax but no recognized authorization token. File-level regex cannot resolve imported helpers, middleware, action registration, or call flow.

**How it's exploited:** A real flaw requires a reachable action whose mutation succeeds without authorization. The module does not replay an anonymous action call, so it reports a candidate rather than a confirmed bypass.

**Fix:** Enforce an explicit auth check at the start of every state-changing Server Action, not just UI or middleware.`

	ModuleConfirmation = "Candidate when source-like code combines server directive and mutations without recognized auth; confirmation requires call-graph review or an unauthorized action replay"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "light"}
)
