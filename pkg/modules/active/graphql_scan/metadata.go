package graphql_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-scan"
	ModuleName  = "GraphQL Security Scanner"
	ModuleShort = "Tests GraphQL endpoints for introspection, injection, and batching vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A reachable GraphQL endpoint was found and exhibits one or more security weaknesses: introspection is enabled (the full API schema with every type, field, and argument is exposed), a field argument leaks database error messages indicating SQL injection, or the endpoint accepts batched queries (array-style or alias-style). Each weakness is reported as its own finding, and together they widen the attack surface of the API.

**How it's exploited:** With introspection on, an attacker maps the entire schema to discover hidden mutations and sensitive fields, then targets them directly. An injectable argument lets an attacker read or alter database contents through crafted SQL. Query batching lets an attacker pack many operations into a single HTTP request to bypass rate limiting and brute-force or amplify denial-of-service attempts.

**Fix:** Disable introspection in production, use parameterized queries or an ORM for all resolver data access, and cap or disable query batching while enforcing per-operation rate limits and query depth/complexity limits.`

	ModuleConfirmation = "Confirmed when GraphQL endpoint responds to introspection queries, SQL payloads produce database errors, or batch queries execute successfully"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "injection", "info-disclosure", "moderate"}
)
