package client_auth_guard

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-auth-guard"
	ModuleName  = "Client Auth Guard Check"
	ModuleShort = "Detects client-only auth guards without server-side enforcement"
)

var (
	ModuleDesc = `**What it means:** A Next.js client component ("use client") performs an authentication redirect from a useEffect hook. This is an observation only: middleware, server components, route handlers, or backend APIs normally enforce authorization outside the client bundle and cannot be ruled out from this response.

**How it's exploited:** An attacker disables JavaScript, drops the redirect, or reads the response before useEffect fires to view the protected component and its data, reaching restricted content.

**Fix:** Enforce auth on the server (middleware, a server component, or route handler); treat the client redirect only as a UX hint.`

	ModuleConfirmation = "Observation only; confirmation requires an anonymous runtime request or repository-wide server authorization trace"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"authentication", "javascript", "light"}
)
