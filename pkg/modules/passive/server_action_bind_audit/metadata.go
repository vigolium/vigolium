package server_action_bind_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-bind-audit"
	ModuleName  = "Server Action Bind Audit"
	ModuleShort = "Detects Server Action .bind() with sensitive identifiers risking IDOR"
)

var (
	ModuleDesc = `## Description
Scans JavaScript and TypeScript response bodies for Next.js Server Actions that use
.bind() to pass sensitive identifiers (IDs, slugs, resource references) as arguments.
Bound arguments are not encrypted and can be tampered with by the client. If the action
does not re-authorize the resource on the server side, this creates an IDOR vulnerability
where users can modify other users' resources by changing the bound ID.

## Notes
- Passive only - does not send any HTTP requests
- Detects .bind(null, <identifier>) patterns in server component code
- Flags when bound values look like resource identifiers (id, userId, postId, etc.)
- Cross-references with authorization check patterns inside the action body
- Deduplicates by host+path
- CWE-639: Authorization Bypass Through User-Controlled Key

## References
- https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations#passing-additional-arguments
- https://nextjs.org/blog/security-nextjs-server-components-actions
- https://cwe.mitre.org/data/definitions/639.html`

	ModuleConfirmation = "Confirmed when .bind() passes identifiers to a Server Action without re-authorization in the action body"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "idor", "light"}
)
