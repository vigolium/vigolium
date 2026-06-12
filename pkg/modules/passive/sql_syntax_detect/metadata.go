package sql_syntax_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sql-syntax-detect"
	ModuleName  = "SQL Syntax in Request Detection"
	ModuleShort = "Detects SQL syntax in HTTP request parameter values"
)

var (
	ModuleDesc = `**What it means:** An HTTP request parameter value contains raw SQL syntax (for example SELECT ... FROM, UNION SELECT, INSERT INTO, DELETE FROM, or a WHERE/AND/OR comparison clause). This is an informational, passive observation: it does not prove a SQL injection vulnerability exists, only that SQL-shaped input reached the application. It often reflects either an in-progress injection attempt against the app or a design where SQL fragments are passed through client-controlled parameters.

**How it's exploited:** If the application concatenates such parameter values into database queries instead of using parameterized statements, an attacker can inject SQL to read, modify, or delete data, bypass authentication, or in some cases reach the underlying host. This finding marks the parameter as a candidate worth confirming with active SQL injection testing; on its own it indicates attack surface, not a confirmed exploit.

**Fix:** Use parameterized queries or prepared statements for all database access and never build SQL by concatenating untrusted request parameter values.`

	ModuleConfirmation = "Indicated when request parameter values contain SQL statement patterns"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"sqli", "injection", "light"}
)
