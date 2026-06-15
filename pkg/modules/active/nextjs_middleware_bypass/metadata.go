package nextjs_middleware_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-middleware-bypass"
	ModuleName  = "Next.js Middleware Bypass"
	ModuleShort = "Detects Next.js middleware authentication bypass via header injection and path manipulation"
)

var (
	ModuleDesc = `**What it means:** A Next.js endpoint that returned 401/403 from its auth middleware instead returns a real 200 page when a crafted header or path is sent, skipping the gating middleware - a critical access-control bypass exposing privileged pages.

**How it's exploited:** An attacker resends the denied request with the x-middleware-subrequest header (CVE-2025-29927) to pose as an internal subrequest, or rewrites the path so the router resolves the protected route but the middleware matcher does not, reaching admin functions without credentials.

**Fix:** Upgrade Next.js and enforce authorization inside route handlers, not solely in middleware a settable header can bypass.`

	ModuleConfirmation = "Confirmed when a bypass technique changes the response from 401/403 to 200 with non-error content"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "moderate"}
)
