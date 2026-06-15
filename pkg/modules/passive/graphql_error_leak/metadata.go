package graphql_error_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-error-leak"
	ModuleName  = "GraphQL Error Leak"
	ModuleShort = "Detects verbose GraphQL errors exposing schema and resolver details"
)

var (
	ModuleDesc = `**What it means:** A GraphQL endpoint returned a verbose error that leaks internal details such as field-name suggestions, type and enum names, resolver paths, database/ORM errors, or stack traces. This over-shares schema and backend internals even when introspection is disabled.

**How it's exploited:** An attacker submits malformed queries and reads the errors to reconstruct the schema, uncover hidden fields, and fingerprint the database and framework, making it far easier to target authorization gaps, injection, or version-specific bugs.

**Fix:** Disable verbose and debug error output in production, returning generic GraphQL errors with stack traces, field suggestions, and database errors stripped.`

	ModuleConfirmation = "Confirmed when JSON response contains GraphQL error objects with internal details such as field suggestions, resolver paths, or stack traces"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"graphql", "info-disclosure", "light"}
)
