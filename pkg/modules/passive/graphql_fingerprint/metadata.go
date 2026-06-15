package graphql_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-fingerprint"
	ModuleName  = "GraphQL Endpoint Fingerprint"
	ModuleShort = "Identifies GraphQL endpoints from request paths and response body markers"
)

var (
	ModuleDesc = `**What it means:** A GraphQL API endpoint was identified, from a known path (/graphql, /api/graphql, /graphiql, /playground) or a JSON response carrying the GraphQL errors array. An informational fingerprint that pinpoints a sensitive part of the API attack surface.

**How it's exploited:** Knowing the endpoint exists lets an attacker focus on GraphQL-specific attacks: introspection to dump the schema, nested or batched queries for denial of service, aliasing to bypass rate limits, and probing resolvers for injection.

**Fix:** Restrict or remove unauthenticated GraphQL IDEs, disable introspection in production, and enforce authentication plus query depth and cost limits.`

	ModuleConfirmation = "Confirmed when a GraphQL endpoint path or response body shape is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "api", "fingerprint", "light"}
)
