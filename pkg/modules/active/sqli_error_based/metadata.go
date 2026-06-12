package sqli_error_based

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-error-based"
	ModuleName  = "SQLi Error Based"
	ModuleShort = "Detects SQLi via error messages"
)

var (
	ModuleDesc = `**What it means:** A parameter on this endpoint is vulnerable to error-based SQL injection: the value is concatenated into a backend SQL query without proper escaping, so injecting broken SQL syntax makes the database raise an error that leaks back in the response. This is a critical flaw because the same injection point lets an attacker rewrite the query itself.

**How it's exploited:** An attacker injects characters that break the query (such as an unbalanced quote or parenthesis) to confirm the flaw via the leaked DBMS error, then crafts payloads (UNION, boolean, or stacked clauses) to read or modify arbitrary data, dump credentials and password hashes, and often pivot to deeper compromise. The detector identifies the specific engine (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2, and many others) by matching driver and error signatures, after confirming the error reproduces and is absent from a clean control request.

**Fix:** Use parameterized queries or prepared statements for every database call, validate and reject unexpected input, and suppress detailed database error messages in responses.`

	ModuleConfirmation = "Confirmed when injected SQL syntax triggers a database error pattern in the response body"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "moderate"}
)
