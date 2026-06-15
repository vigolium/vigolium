package sql_syntax_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sql-syntax-detect"
	ModuleName  = "SQL Syntax in Request Detection"
	ModuleShort = "Detects SQL syntax in HTTP request parameter values"
)

var (
	ModuleDesc = `**What it means:** An HTTP request parameter value contains raw SQL syntax (for example UNION SELECT or a WHERE/AND/OR clause). Informational passive observation: it does not prove SQL injection exists, only that SQL-shaped input reached the application, often an in-progress attempt or SQL passed through parameters.

**How it's exploited:** If the app concatenates such values into queries instead of parameterizing, an attacker can inject SQL to read, modify, or delete data or bypass authentication. Marks the parameter for active SQL injection testing.

**Fix:** Use parameterized queries or prepared statements for all database access and never build SQL from untrusted parameters.`

	ModuleConfirmation = "Indicated when request parameter values contain SQL statement patterns"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"sqli", "injection", "light"}
)
