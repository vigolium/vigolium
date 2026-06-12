package graphql_introspection_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-introspection-detect"
	ModuleName  = "GraphQL Introspection Leak Detect"
	ModuleShort = "Detects GraphQL introspection responses that expose the full API schema"
)

var (
	ModuleDesc = `**What it means:** A GraphQL endpoint returned an introspection response, meaning its full API schema is queryable by anyone. The response body contains introspection fields (__schema or __type) alongside schema markers such as queryType, mutationType, subscriptionType, or types, exposing every type, field, query, and mutation the API defines.

**How it's exploited:** Introspection hands an attacker a complete map of the API, removing the guesswork from reconnaissance. They can enumerate hidden or undocumented operations, discover sensitive fields and admin-only mutations, and craft precise queries to probe for authorization gaps, injection, and other flaws far faster than blind fuzzing would allow.

**Fix:** Disable GraphQL introspection in production (for example, set introspection to false in the server config), and restrict schema access to trusted internal or development environments only.`

	ModuleConfirmation = "Confirmed when response contains GraphQL introspection fields (__schema/__type) with schema definition markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"graphql", "api", "info-disclosure", "light"}
)
