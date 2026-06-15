package sqli_error_based

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-error-based"
	ModuleName  = "SQLi Error Based"
	ModuleShort = "Detects SQLi via error messages"
)

var (
	ModuleDesc = `**What it means:** A parameter is concatenated into a backend SQL query without escaping (error-based SQL injection): injecting broken syntax raises a leaked database error, and the same injection point lets an attacker rewrite the query.

**How it's exploited:** An attacker injects an unbalanced quote to confirm the flaw via the leaked DBMS error, then uses UNION or boolean payloads to read or modify data, dump credential hashes, and pivot deeper - the error is confirmed absent from a clean control request.

**Fix:** Use parameterized queries or prepared statements for database calls, validate input, and suppress detailed database error messages.`

	ModuleConfirmation = "Confirmed when injected SQL syntax triggers a database error pattern in the response body"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "moderate"}
)
