package forbidden_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "forbidden-bypass"
	ModuleName  = "403/401 Forbidden Bypass"
	ModuleShort = "Detects bypass methods for 403/401 Forbidden responses"
)

var (
	ModuleDesc = `**What it means:** A resource returning 401 or 403 can be reached anyway via a simple request trick, so its access-control check does not hold. A tweaked request turned the forbidden response into a 200 with distinct content.

**How it's exploited:** An attacker reaches a protected page or API by mutating the path (added segments, encoded slashes, case changes), spoofing headers like X-Forwarded-For, X-Original-URL, or X-Forwarded-User, or abusing the Next.js x-middleware-subrequest bypass (CVE-2025-29927).

**Fix:** Enforce authorization at the application layer for every request regardless of path encoding, method, or proxy/identity headers, and strip untrusted forwarding headers.`

	ModuleConfirmation = "Confirmed when a bypass technique produces a non-403 response with valid content for a previously forbidden resource"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
