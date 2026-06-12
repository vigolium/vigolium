package forbidden_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "forbidden-bypass"
	ModuleName  = "403/401 Forbidden Bypass"
	ModuleShort = "Detects bypass methods for 403/401 Forbidden responses"
)

var (
	ModuleDesc = `**What it means:** A resource that returns 401 Unauthorized or 403 Forbidden can be reached anyway by a simple request trick, so the access-control check that was supposed to protect it does not actually hold. The scanner confirmed a tweaked request that turned the forbidden response into a 200 serving distinct content for the same resource, after ruling out catch-all pages, soft-404s, login redirects, and one-off flaps.

**How it's exploited:** An attacker reaches a protected page or API without proper authorization by mutating the path (added segments, encoded slashes, trailing characters, case changes), spoofing IP/rewrite headers such as X-Forwarded-For or X-Original-URL, asserting a privileged identity via trusted reverse-proxy/SSO headers like X-Forwarded-User or X-Auth-Request-Email, abusing the Next.js x-middleware-subrequest bypass (CVE-2025-29927), or tampering with the HTTP method or method-override headers. The result is unauthorized access to restricted functionality or data.

**Fix:** Enforce authorization at the application layer for every request regardless of path encoding, method, or client-supplied proxy/identity headers, and strip untrusted forwarding headers at the edge.`

	ModuleConfirmation = "Confirmed when a bypass technique produces a non-403 response with valid content for a previously forbidden resource"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
