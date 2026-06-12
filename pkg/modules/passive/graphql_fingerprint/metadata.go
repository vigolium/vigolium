package graphql_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-fingerprint"
	ModuleName  = "GraphQL Endpoint Fingerprint"
	ModuleShort = "Identifies GraphQL endpoints from request paths and response body markers"
)

var (
	ModuleDesc = `**What it means:** A GraphQL API endpoint was identified on this host, either from a known GraphQL URL path (such as /graphql, /v1/graphql, /api/graphql, /graphiql, /playground, or /altair) or from a JSON response carrying the GraphQL errors array with location entries. This is an informational fingerprint, not a vulnerability on its own, but it pinpoints a sensitive part of the API attack surface.

**How it's exploited:** Knowing a GraphQL endpoint exists lets an attacker focus on GraphQL-specific attacks: introspection queries to dump the full schema, deeply nested or batched queries for denial of service, field suggestion and aliasing to bypass rate limits, and probing resolvers for injection or broken authorization. Exposed in-browser IDEs like GraphiQL, Playground, or Altair further simplify crafting and running these queries.

**Fix:** Restrict or remove unauthenticated GraphQL IDEs, disable introspection in production, and enforce authentication, query depth and cost limits on the endpoint.`

	ModuleConfirmation = "Confirmed when a GraphQL endpoint path or response body shape is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "api", "fingerprint", "light"}
)
