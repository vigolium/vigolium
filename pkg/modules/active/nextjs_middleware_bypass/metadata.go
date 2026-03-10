package nextjs_middleware_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-middleware-bypass"
	ModuleName  = "Next.js Middleware Bypass"
	ModuleShort = "Detects Next.js middleware authentication bypass via header injection and path manipulation"
)

var (
	ModuleDesc = `## Description
Tests for Next.js middleware bypass vulnerabilities including CVE-2025-29927 and
path normalization issues. Next.js middleware runs before route handlers and is
commonly used for authentication. Certain header injections and path manipulations
can skip middleware execution entirely.

## Notes
- Only activates on 401/403 responses from Next.js hosts
- Tests x-middleware-subrequest header injection (CVE-2025-29927)
- Tests path normalization bypasses (double slashes, URL encoding, locale prefixes)
- Deduplicates with per-host limit (max 20 attempts per host)
- Validates bypass by checking status change from 401/403 to 200

## References
- https://github.com/advisories/GHSA-f82v-jwr5-mffw
- https://zhero-web-sec.github.io/research-and-things/nextjs-middleware-bypass`

	ModuleConfirmation = "Confirmed when a bypass technique changes the response from 401/403 to 200 with non-error content"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"nextjs", "javascript", "authentication", "moderate"}
)
