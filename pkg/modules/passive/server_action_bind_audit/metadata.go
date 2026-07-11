package server_action_bind_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-bind-audit"
	ModuleName  = "Server Action Bind Audit"
	ModuleShort = "Detects Server Action .bind() with sensitive identifiers risking IDOR"
)

var (
	ModuleDesc = `**What it means:** Source-like JS/TS contains a server directive and .bind(null, identifier) using an ID-shaped name, with no recognized authorization token elsewhere in the file. Identifier names alone do not establish ownership semantics.

**How it's exploited:** A real IDOR requires the bound value to be attacker-tamperable, reach a resource lookup, and succeed for another principal without an ownership check. This module does not trace or replay that flow.

**Fix:** Re-authorize every resource inside the action body by checking the session against the bound identifier, never client IDs.`

	ModuleConfirmation = "Candidate when a server-action file binds an ID-shaped argument without recognized auth; confirmation requires ownership-flow tracing or cross-user replay"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "idor", "light"}
)
