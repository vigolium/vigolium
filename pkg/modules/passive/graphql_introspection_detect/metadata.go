package graphql_introspection_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-introspection-detect"
	ModuleName  = "GraphQL Introspection Leak Detect"
	ModuleShort = "Detects GraphQL introspection responses that expose the full API schema"
)

var (
	ModuleDesc = `## Description
Passively detects GraphQL introspection responses that leak the full API schema,
including types, queries, mutations, and subscriptions.

## Notes
- Checks JSON response bodies for introspection-specific fields (__schema, __type)
- Requires confirmation fields (queryType, mutationType, subscriptionType, types) to avoid false positives
- Runs per-request to catch endpoint-specific disclosures

## References
- https://graphql.org/learn/introspection/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL`

	ModuleConfirmation = "Confirmed when response contains GraphQL introspection fields (__schema/__type) with schema definition markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"graphql", "api", "info-disclosure", "light"}
)
