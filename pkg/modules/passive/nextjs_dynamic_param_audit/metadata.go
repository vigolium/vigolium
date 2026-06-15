package nextjs_dynamic_param_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-dynamic-param-audit"
	ModuleName  = "Next.js Dynamic Param Audit"
	ModuleShort = "Detects unsafe usage of dynamic route params without validation"
)

var (
	ModuleDesc = `**What it means:** Next.js source in a JS/TS response uses dynamic route params or searchParams directly in a query, authorization decision, or redirect target, with no validation first. A static source-pattern lead for review, not a confirmed exploit.

**How it's exploited:** The unguarded sink points to a likely flaw: params in a query enable SQL or NoSQL injection, searchParams in auth checks (isAdmin, role, token) allow privilege escalation, and searchParams as a redirect target enable open redirect.

**Fix:** Validate and coerce every param and searchParam (Zod, parseInt, or UUID parser) before using it in queries, auth logic, or redirects.`

	ModuleConfirmation = "Confirmed when dynamic params or searchParams are used directly in sensitive operations without validation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "injection", "light"}
)
