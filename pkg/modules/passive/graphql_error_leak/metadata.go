package graphql_error_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-error-leak"
	ModuleName  = "GraphQL Error Leak"
	ModuleShort = "Detects verbose GraphQL errors exposing schema and resolver details"
)

var (
	ModuleDesc = `**What it means:** A GraphQL endpoint returned a verbose error response that leaks internal implementation details, such as field-name suggestions ("Did you mean ...?"), type and enum names, resolver paths, expected variable types, database/ORM errors, or stack traces. This over-shares schema and backend internals that should stay private, expanding the attacker's view of the API even when introspection is disabled.

**How it's exploited:** An attacker submits malformed or probing GraphQL queries and reads the error messages to reconstruct the schema, uncover hidden fields and types, and fingerprint the database and framework. That mapped attack surface and the disclosed backend technologies make it far easier to target authorization gaps, injection, or known version-specific bugs in follow-up attacks.

**Fix:** Disable verbose and debug error output in production by returning generic GraphQL error messages, stripping stack traces, field suggestions, and database errors before responses leave the server.`

	ModuleConfirmation = "Confirmed when JSON response contains GraphQL error objects with internal details such as field suggestions, resolver paths, or stack traces"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"graphql", "info-disclosure", "light"}
)
