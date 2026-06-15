package client_auth_guard

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-auth-guard"
	ModuleName  = "Client Auth Guard Check"
	ModuleShort = "Detects client-only auth guards without server-side enforcement"
)

var (
	ModuleDesc = `**What it means:** A Next.js client component ("use client") enforces auth only in the browser, redirecting unauthenticated users from a useEffect hook with no server-side session check. Running in client JavaScript, the guard does not protect the server data or page, so the access control is cosmetic.

**How it's exploited:** An attacker disables JavaScript, drops the redirect, or reads the response before useEffect fires to view the protected component and its data, reaching restricted content.

**Fix:** Enforce auth on the server (middleware, a server component, or route handler); treat the client redirect only as a UX hint.`

	ModuleConfirmation = "Confirmed when a client component implements auth redirect via useEffect without server-side auth"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"authentication", "javascript", "light"}
)
