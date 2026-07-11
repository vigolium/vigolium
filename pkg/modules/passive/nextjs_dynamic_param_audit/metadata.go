package nextjs_dynamic_param_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-dynamic-param-audit"
	ModuleName  = "Next.js Dynamic Param Audit"
	ModuleShort = "Detects unsafe usage of dynamic route params without validation"
)

var (
	ModuleDesc = `**What it means:** A source-like JS/TS file contains route/search parameter syntax near a database, authorization, SQL, or redirect pattern, with no recognized validation token elsewhere in the file.

**How it's exploited:** A real flaw requires the same attacker-controlled value to reach the sink without imported/manual validation. Regex proximity cannot establish that flow or impact, so every result remains a candidate.

**Fix:** Validate and coerce every param and searchParam (Zod, parseInt, or UUID parser) before using it in queries, auth logic, or redirects.`

	ModuleConfirmation = "Candidate when source-like code co-locates param and sensitive-sink patterns without recognized validation; taint tracing or dynamic impact is required"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"nextjs", "javascript", "injection", "light"}
)
