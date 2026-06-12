package nosqli_error_based

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nosqli-error-based"
	ModuleName  = "NoSQLi Error Based"
	ModuleShort = "Detects NoSQL injection via error messages and operator injection"
)

var (
	ModuleDesc = `**What it means:** A request parameter is passed unsanitized into a NoSQL database query. The module injected NoSQL operators and syntax (such as MongoDB query operators, quotes, and JavaScript clauses) and observed a database-specific error message appear in the response that was absent from the original body, proving the input reaches the query engine. This is a critical injection flaw equivalent in impact to classic SQL injection.

**How it's exploited:** An attacker shapes operator payloads to authenticate without valid credentials, bypass query filters to read records belonging to other users, extract data through boolean or error-based oracles, or run server-side JavaScript on engines that allow it, leading to data theft, authentication bypass, or full database compromise.

**Fix:** Never build queries from raw user input. Use the driver's parameterized query and operator-safe APIs, reject objects where a scalar is expected, validate and type-cast all inputs, and disable server-side JavaScript evaluation on the database.`

	ModuleConfirmation = "Confirmed when injected NoSQL operators trigger database error patterns in the response body"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "moderate"}
)
