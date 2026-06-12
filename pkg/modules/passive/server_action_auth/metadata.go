package server_action_auth

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-auth"
	ModuleName  = "Server Action Auth Check"
	ModuleShort = "Detects Next.js Server Actions missing authorization checks"
)

var (
	ModuleDesc = `**What it means:** A Next.js Server Action found in a served JavaScript or TypeScript bundle carries a "use server" directive and performs a state-changing database or write operation, but the code shows no nearby authorization check (no session lookup, auth() call, token verification, or similar). Server Actions run on the server yet are directly invocable from the client, so a missing access-control guard means any visitor may be able to trigger the mutation. This is a passive, source-pattern signal (severity High, confidence Tentative) and may have false positives when auth is enforced elsewhere, such as in middleware.

**How it's exploited:** An attacker reads the action identifier from the public client bundle and crafts a direct POST to the Server Action endpoint, invoking the create, update, or delete operation while unauthenticated or as a low-privileged user, leading to unauthorized data modification or deletion.

**Fix:** Enforce an explicit authentication and authorization check at the start of every state-changing Server Action rather than relying solely on UI gating or middleware.`

	ModuleConfirmation = "Confirmed when a Server Action contains mutation operations but no authorization checks"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "light"}
)
