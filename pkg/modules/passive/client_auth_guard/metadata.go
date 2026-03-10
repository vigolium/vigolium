package client_auth_guard

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-auth-guard"
	ModuleName  = "Client Auth Guard Check"
	ModuleShort = "Detects client-only auth guards without server-side enforcement"
)

var (
	ModuleDesc = `## Description
Scans JavaScript and TypeScript response bodies for Next.js client components that
implement authentication guards purely on the client side using useEffect redirects.
Client-side auth checks can be trivially bypassed by disabling JavaScript or
manipulating the DOM, leaving protected routes accessible without authentication.

## Notes
- Passive only - does not send any HTTP requests
- Detects "use client" directive combined with useEffect-based auth redirects
- Flags when no server-side auth indicators are found alongside client redirects
- Covers router.push/replace to login/signin/auth and window.location redirects
- Deduplicates by host+path
- CWE-862: Missing Authorization

## References
- https://nextjs.org/docs/app/building-your-application/authentication
- https://cwe.mitre.org/data/definitions/862.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema`

	ModuleConfirmation = "Confirmed when a client component implements auth redirect via useEffect without server-side auth"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"authentication", "javascript", "light"}
)
