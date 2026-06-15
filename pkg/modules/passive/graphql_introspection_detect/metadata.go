package graphql_introspection_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-introspection-detect"
	ModuleName  = "GraphQL Introspection Leak Detect"
	ModuleShort = "Detects GraphQL introspection responses that expose the full API schema"
)

var (
	ModuleDesc = `**What it means:** A GraphQL endpoint returned an introspection response, so its full API schema is queryable by anyone. The body contains introspection fields (__schema or __type) with markers like queryType or types, exposing every type, field, query, and mutation.

**How it's exploited:** Introspection hands an attacker a complete map of the API. They enumerate hidden operations, discover sensitive fields and admin-only mutations, and craft precise queries to probe for authorization gaps and injection far faster than blind fuzzing.

**Fix:** Disable GraphQL introspection in production (set introspection to false) and restrict schema access to trusted internal or development environments only.`

	ModuleConfirmation = "Confirmed when response contains GraphQL introspection fields (__schema/__type) with schema definition markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"graphql", "api", "info-disclosure", "light"}
)
