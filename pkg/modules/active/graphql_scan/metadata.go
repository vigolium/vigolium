package graphql_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-graphql-scan"
	ModuleName  = "GraphQL Security Scanner"
	ModuleShort = "Tests GraphQL endpoints for introspection, injection, and batching vulnerabilities"
)

var (
	ModuleDesc = `## Description
Discovers GraphQL endpoints and tests them for common security misconfigurations including
enabled introspection, SQL injection through GraphQL arguments, and query batching abuse.

## Notes
- Probes 8 common GraphQL endpoint paths
- Tests both POST and GET request methods for endpoint discovery
- Checks for enabled introspection (information disclosure)
- Injects SQL payloads into discovered or common field arguments
- Tests for query batching support (rate limiting bypass)
- Runs once per host

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
- https://graphql.org/learn/introspection/`

	ModuleConfirmation = "Confirmed when GraphQL endpoint responds to introspection queries, SQL payloads produce database errors, or batch queries execute successfully"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "injection", "info-disclosure", "moderate"}
)
