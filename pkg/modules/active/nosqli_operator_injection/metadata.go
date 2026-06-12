package nosqli_operator_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nosqli-operator-injection"
	ModuleName  = "NoSQL Operator Injection"
	ModuleShort = "Detects MongoDB operator injection ($ne, $gt, $regex, $where) for auth bypass and data exfiltration"
)

var (
	ModuleDesc = `**What it means:** A parameter is passed into a NoSQL query (typically MongoDB) without being treated as a plain string, so injected query operators like $ne, $gt, $regex, $where, or array syntax such as param[$ne]= are interpreted as query logic instead of literal input. This lets an attacker alter the query's meaning, defeating authentication and access controls.

**How it's exploited:** An attacker replaces an expected value with an operator that always matches (for example {"$ne":""} or {"$gt":""}) to bypass a login or authorization check and act as another user, or uses $regex / $where tautologies to make a lookup return records it should not, exfiltrating data. The scanner confirms this by observing a reproducible 401/403-to-2xx authentication bypass, a stable always-true vs always-false boolean response differential, a large reproducible response-body growth, or a time delay from an injected sleep.

**Fix:** Cast user input to the expected scalar type and reject objects/arrays where strings are expected, and use parameterized query construction so user data can never supply query operators.`

	ModuleConfirmation = "Confirmed when NoSQL operator injection causes authentication bypass, data exfiltration, or measurable behavioral change"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "sqli", "moderate"}
)
