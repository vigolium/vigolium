package nextjs_dynamic_param_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-dynamic-param-audit"
	ModuleName  = "Next.js Dynamic Param Audit"
	ModuleShort = "Detects unsafe usage of dynamic route params without validation"
)

var (
	ModuleDesc = `**What it means:** This finding flags Next.js page or route-handler source served in a JavaScript/TypeScript response that consumes user-controlled dynamic route params or URL searchParams directly in a database query, SQL string, authorization decision, or redirect target, with no schema validation, type coercion, or sanitization applied first. It is a static source-pattern observation, not a confirmed exploit, so it is reported as a Medium-severity lead for manual review.

**How it's exploited:** Because the input is fully attacker-controlled, the unguarded usage points to a likely vulnerability at that sink: params flowing into a query enable SQL or NoSQL injection, searchParams used in auth checks (isAdmin, role, token) allow client-controlled privilege escalation, and searchParams used as a redirect target enable open redirect. A reviewer would trace the flagged sink to confirm and weaponize it.

**Fix:** Validate and coerce every dynamic param and searchParam (for example with a Zod schema, parseInt, or a UUID parser) before using it in queries, authorization logic, or redirects.`

	ModuleConfirmation = "Confirmed when dynamic params or searchParams are used directly in sensitive operations without validation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "injection", "light"}
)
