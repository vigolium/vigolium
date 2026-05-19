package sqli_error_based

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-error-based"
	ModuleName  = "SQLi Error Based"
	ModuleShort = "Detects SQLi via error messages"
)

var (
	ModuleDesc = `## Description
Detects SQL injection vulnerabilities by injecting SQL syntax into parameters and
analyzing response bodies for database error messages from MySQL, PostgreSQL, MSSQL,
Oracle, and SQLite.

## Notes
- Tests each insertion point independently
- Uses request deduplication to avoid redundant checks
- Skips hosts that have exceeded the error threshold

## References
- https://owasp.org/www-community/attacks/SQL_Injection`

	ModuleConfirmation = "Confirmed when injected SQL syntax triggers a database error pattern in the response body"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "moderate"}
)
