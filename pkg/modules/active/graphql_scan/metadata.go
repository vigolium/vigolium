package graphql_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-scan"
	ModuleName  = "GraphQL Security Scanner"
	ModuleShort = "Tests GraphQL endpoints for introspection, injection, and batching vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A reachable GraphQL endpoint shows one or more weaknesses: introspection is enabled (the full schema is exposed), a field argument leaks database errors indicating SQL injection, or the endpoint accepts batched queries.

**How it's exploited:** Introspection maps the schema to reveal hidden mutations and sensitive fields. An injectable argument reads or alters data via crafted SQL. Batching packs many operations into one request to bypass rate limiting and amplify denial-of-service.

**Fix:** Disable introspection in production, use parameterized queries in resolvers, and cap batching while enforcing rate limits and query depth limits.`

	ModuleConfirmation = "Confirmed when GraphQL endpoint responds to introspection queries, SQL payloads produce database errors, or batch queries execute successfully"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "injection", "info-disclosure", "moderate"}
)
