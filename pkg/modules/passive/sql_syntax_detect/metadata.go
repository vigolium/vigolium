package sql_syntax_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-sql-syntax-detect"
	ModuleName  = "SQL Syntax in Request Detection"
	ModuleShort = "Detects SQL syntax in HTTP request parameter values"
)

var (
	ModuleDesc = `## Description
Passively detects SQL statements and keywords in HTTP request parameter values,
which may indicate SQL injection attempts or unsafe parameter handling.

## Notes
- Matches SQL statements: SELECT..FROM, INSERT INTO, UPDATE..SET, DELETE FROM, UNION SELECT, etc.
- Secondary check for SQL keyword pairs: WHERE/AND/OR with comparison operators
- URL-decodes parameter values before checking
- Minimum value length of 8 characters to reduce false positives

## References
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html`

	ModuleConfirmation = "Indicated when request parameter values contain SQL statement patterns"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"sqli", "injection", "light"}
)
