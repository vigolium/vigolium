package nosqli_error_based

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nosqli-error-based"
	ModuleName  = "NoSQLi Error Based"
	ModuleShort = "Detects NoSQL injection via error messages and operator injection"
)

var (
	ModuleDesc = `**What it means:** A request parameter flows unsanitized into a NoSQL query. Injected operators made a database-specific error appear that was absent from the original body, proving input reaches the query engine - an injection flaw on par with classic SQL injection.

**How it's exploited:** An attacker shapes operator payloads to authenticate without credentials, read other users' records, extract data via boolean or error-based oracles, or run server-side JavaScript where allowed, leading to data theft.

**Fix:** Never build queries from raw input. Use parameterized, operator-safe driver APIs, reject objects where a scalar is expected, and disable server-side JavaScript evaluation.`

	ModuleConfirmation = "Confirmed when injected NoSQL operators trigger database error patterns in the response body"
	// Error-string matching is inherently heuristic — a driver-error pattern can
	// surface in non-exploitable contexts (a reflected message, an upstream
	// component's log line, an incidental token in a bundle) even after the
	// static-asset, corroboration, reproduce, and clean-control gates. Report
	// High/Tentative so the finding is treated as a lead to verify, not a
	// definitive injection.
	ModuleSeverity   = severity.High
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"injection", "sqli", "moderate"}
)
