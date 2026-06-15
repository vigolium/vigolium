package server_action_auth

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-auth"
	ModuleName  = "Server Action Auth Check"
	ModuleShort = "Detects Next.js Server Actions missing authorization checks"
)

var (
	ModuleDesc = `**What it means:** A Next.js Server Action in a served JS bundle has a "use server" directive and a state-changing write, but no nearby authorization check (session lookup, auth() call, or token verification). Server Actions are invocable directly from the client, so a missing guard lets any visitor trigger the mutation. This can false-positive when auth sits in middleware.

**How it's exploited:** An attacker reads the action identifier from the public bundle and crafts a direct POST, invoking the write unauthenticated.

**Fix:** Enforce an explicit auth check at the start of every state-changing Server Action, not just UI or middleware.`

	ModuleConfirmation = "Confirmed when a Server Action contains mutation operations but no authorization checks"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "light"}
)
