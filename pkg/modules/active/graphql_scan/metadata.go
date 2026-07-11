package graphql_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-scan"
	ModuleName  = "GraphQL Security Scanner"
	ModuleShort = "Tests GraphQL endpoints for introspection, injection, and batching vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A confirmed GraphQL endpoint exposes security-relevant behavior. Introspection and consoles are observations; batching, depth, predictable same-principal lookup, SQL-error differences, and reflection are candidates. A finding requires altered query logic or other demonstrated impact.

**How it's exploited:** Attackers enumerate the schema, stress query execution, probe object access, inject resolver inputs, or turn reflected errors into executable markup.

**Fix:** Restrict introspection and consoles, parameterize resolvers, limit batching and complexity, authorize every object, and encode errors.`

	ModuleConfirmation = "A live endpoint requires an exact, reproduced data.__typename response; each check is then classified as observation, candidate, or finding according to whether exploit impact is directly demonstrated"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "injection", "info-disclosure", "idor", "bola", "xss", "dos", "batching", "console", "moderate"}
)
