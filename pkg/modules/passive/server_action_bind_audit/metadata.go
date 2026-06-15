package server_action_bind_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-bind-audit"
	ModuleName  = "Server Action Bind Audit"
	ModuleShort = "Detects Server Action .bind() with sensitive identifiers risking IDOR"
)

var (
	ModuleDesc = `**What it means:** Shipped JS code creates a Next.js Server Action with .bind(null, identifier) where the bound argument looks like a resource reference (id, userId, postId), with no nearby authorization check. Bound arguments reach the browser unencrypted and are tamperable, so without an ownership re-check this is a likely IDOR (CWE-639).

**How it's exploited:** An attacker who can call the action swaps in another user's identifier and, if the action trusts that ID, reads or deletes others' resources.

**Fix:** Re-authorize every resource inside the action body by checking the session against the bound identifier, never client IDs.`

	ModuleConfirmation = "Confirmed when .bind() passes identifiers to a Server Action without re-authorization in the action body"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "idor", "light"}
)
