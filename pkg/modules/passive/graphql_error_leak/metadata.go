package graphql_error_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-error-leak"
	ModuleName  = "GraphQL Error Leak"
	ModuleShort = "Detects verbose GraphQL errors exposing schema and resolver details"
)

var (
	ModuleDesc = `## Description
Passively detects verbose GraphQL error responses that leak internal implementation details
such as resolver names, field suggestions, type information, database errors, and stack traces.
These errors can help attackers enumerate the schema, discover hidden fields, and identify
backend technologies without requiring introspection access.

## Notes
- Checks JSON response bodies for GraphQL error array structure
- Detects field suggestion leaks ("Did you mean ...?")
- Detects resolver/type name exposure in error paths
- Detects database and ORM errors surfaced through GraphQL
- Deduplicates by host+path to avoid redundant findings

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- https://the-bilal-rizwan.medium.com/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696`

	ModuleConfirmation = "Confirmed when JSON response contains GraphQL error objects with internal details such as field suggestions, resolver paths, or stack traces"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"graphql", "info-disclosure", "light"}
)
