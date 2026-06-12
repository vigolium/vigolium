package server_action_bind_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-bind-audit"
	ModuleName  = "Server Action Bind Audit"
	ModuleShort = "Detects Server Action .bind() with sensitive identifiers risking IDOR"
)

var (
	ModuleDesc = `**What it means:** This finding flags shipped JavaScript or TypeScript code where a Next.js Server Action is created with .bind(null, identifier) and the bound argument looks like a resource reference (id, userId, postId, slug, orgId, and similar), with no authorization check (canAccess, isOwner, getSession, requireAuth, and similar) visible in the same code. Bound arguments travel to the browser unencrypted and can be tampered with, so if the server does not re-check ownership this is a likely Insecure Direct Object Reference (IDOR / CWE-639). This is a passive, heuristic source-analysis signal at Tentative confidence: it cannot see server-side authorization and may be a false positive.

**How it's exploited:** An attacker who can call the Server Action substitutes another user's identifier for the bound value and, if the action trusts that ID without verifying ownership, reads, modifies, or deletes resources belonging to other accounts.

**Fix:** Re-authorize every resource inside the Server Action body by checking the current session against the bound identifier instead of trusting client-supplied IDs.`

	ModuleConfirmation = "Confirmed when .bind() passes identifiers to a Server Action without re-authorization in the action body"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "idor", "light"}
)
