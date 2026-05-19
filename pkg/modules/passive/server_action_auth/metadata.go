package server_action_auth

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-action-auth"
	ModuleName  = "Server Action Auth Check"
	ModuleShort = "Detects Next.js Server Actions missing authorization checks"
)

var (
	ModuleDesc = `## Description
Scans JavaScript and TypeScript response bodies for Next.js Server Actions that perform
state-changing operations (database mutations, writes) without any authorization checks.
Server Actions marked with "use server" execute on the server and are directly callable
from the client. If they lack session validation or auth guards, any unauthenticated
user can invoke them to modify data.

## Notes
- Passive only - does not send any HTTP requests
- Detects "use server" directive combined with mutation patterns (create, update, delete, etc.)
- Flags when no authorization patterns are found (getSession, auth(), verifyToken, etc.)
- Deduplicates by host+path
- CWE-862: Missing Authorization

## References
- https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations
- https://cwe.mitre.org/data/definitions/862.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema`

	ModuleConfirmation = "Confirmed when a Server Action contains mutation operations but no authorization checks"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "light"}
)
