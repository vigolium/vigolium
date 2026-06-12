package client_auth_guard

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-auth-guard"
	ModuleName  = "Client Auth Guard Check"
	ModuleShort = "Detects client-only auth guards without server-side enforcement"
)

var (
	ModuleDesc = `**What it means:** A served Next.js client component (marked "use client") enforces authentication only in the browser, redirecting unauthenticated users to a login page from a useEffect hook, with no server-side session check found alongside it. Because the guard runs in client-side JavaScript, it does not actually protect the underlying data or page on the server, so the access control is effectively cosmetic.

**How it's exploited:** An attacker disables JavaScript, intercepts and drops the redirect, or simply reads the response before the useEffect fires to view the protected component and any data it embeds. If the page or its API calls rely on this redirect instead of a server-validated session, unauthenticated users can reach content and functionality meant to be restricted.

**Fix:** Enforce authentication on the server (validate the session in middleware, a server component, or the route handler) and treat the client-side redirect only as a user-experience hint, not as the security control.`

	ModuleConfirmation = "Confirmed when a client component implements auth redirect via useEffect without server-side auth"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"authentication", "javascript", "light"}
)
