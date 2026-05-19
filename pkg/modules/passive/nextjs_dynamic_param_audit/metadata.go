package nextjs_dynamic_param_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-dynamic-param-audit"
	ModuleName  = "Next.js Dynamic Param Audit"
	ModuleShort = "Detects unsafe usage of dynamic route params without validation"
)

var (
	ModuleDesc = `## Description
Scans JavaScript and TypeScript response bodies for Next.js pages and route handlers
that use dynamic route params or searchParams directly in database queries, authorization
decisions, or sensitive operations without runtime validation. Dynamic route segments
([param]) and searchParams are user-controlled strings that must be validated before
use in security-sensitive contexts.

## Notes
- Passive only - does not send any HTTP requests
- Detects params.id, params.slug, searchParams.* used directly in DB queries
- Detects searchParams used in authorization decisions (isAdmin, role, etc.)
- Flags when no schema validation is applied before use
- Deduplicates by host+path
- CWE-20: Improper Input Validation

## References
- https://nextjs.org/docs/app/building-your-application/routing/dynamic-routes
- https://nextjs.org/blog/security-nextjs-server-components-actions
- https://cwe.mitre.org/data/definitions/20.html
- https://cwe.mitre.org/data/definitions/89.html`

	ModuleConfirmation = "Confirmed when dynamic params or searchParams are used directly in sensitive operations without validation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "injection", "light"}
)
