package graphql_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-fingerprint"
	ModuleName  = "GraphQL Endpoint Fingerprint"
	ModuleShort = "Identifies GraphQL endpoints from request paths and response body markers"
)

var (
	ModuleDesc = `## Description
Passively identifies GraphQL endpoints by matching common GraphQL paths
(/graphql, /v1/graphql, /api/graphql) and inspecting JSON responses for
GraphQL-specific shapes ("data", "errors" arrays with locations).

## Signals
- URL path matches a known GraphQL endpoint pattern
- Response body contains a top-level {"data": …} or {"errors": [{"message": …, "locations": [...]}]} shape

## Notes
- Passive only: does not send any HTTP requests
- Publishes "graphql" to the tech registry so graphql-tagged active modules run`

	ModuleConfirmation = "Confirmed when a GraphQL endpoint path or response body shape is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "api", "fingerprint", "light"}
)
