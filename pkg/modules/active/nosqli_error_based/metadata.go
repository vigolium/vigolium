package nosqli_error_based

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-nosqli-error-based"
	ModuleName  = "NoSQLi Error Based"
	ModuleShort = "Detects NoSQL injection via error messages and operator injection"
)

var (
	ModuleDesc = `## Description
Detects NoSQL injection vulnerabilities by injecting MongoDB/NoSQL operators and
syntax into parameters and analyzing response bodies for database error messages.

## Notes
- Tests each insertion point with NoSQL-specific payloads
- Detects MongoDB, CouchDB, and Cassandra error patterns
- Uses request deduplication to avoid redundant checks

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- https://portswigger.net/web-security/nosql-injection`

	ModuleConfirmation = "Confirmed when injected NoSQL operators trigger database error patterns in the response body"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"injection", "sqli", "moderate"}
)
