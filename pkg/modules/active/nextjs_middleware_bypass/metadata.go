package nextjs_middleware_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-middleware-bypass"
	ModuleName  = "Next.js Middleware Bypass"
	ModuleShort = "Detects Next.js middleware authentication bypass via header injection and path manipulation"
)

var (
	ModuleDesc = `**What it means:** A Next.js endpoint that returned 401/403 (its middleware was enforcing authentication or authorization) instead returns a real 200 page when a crafted header or path is sent, meaning the gating middleware is skipped entirely. Because Next.js middleware commonly enforces login, role, and route-protection checks, this is a critical access-control bypass exposing pages or data meant only for privileged users.

**How it's exploited:** An attacker resends the denied request with the x-middleware-subrequest header (CVE-2025-29927), tricking Next.js into treating the call as an internal subrequest that skips middleware, or rewrites the path (double leading slash, URL-encoded dot, null-byte suffix, locale prefix, encoded traversal) so the router resolves the protected route but the middleware matcher does not. Either way they reach protected pages, API responses, or admin functions without valid credentials. The scanner confirms by re-verifying the original stays denied while the crafted request repeatedly returns non-login, non-error 200 content.

**Fix:** Upgrade Next.js and enforce authorization inside the route handlers, not solely in middleware a settable header can bypass.`

	ModuleConfirmation = "Confirmed when a bypass technique changes the response from 401/403 to 200 with non-error content"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "moderate"}
)
