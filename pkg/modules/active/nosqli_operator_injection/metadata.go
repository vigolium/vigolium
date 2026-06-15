package nosqli_operator_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nosqli-operator-injection"
	ModuleName  = "NoSQL Operator Injection"
	ModuleShort = "Detects MongoDB operator injection ($ne, $gt, $regex, $where) for auth bypass and data exfiltration"
)

var (
	ModuleDesc = `**What it means:** A parameter flows into a NoSQL query (typically MongoDB) without being treated as a plain string, so injected operators like $ne, $gt, $regex, $where, or array syntax such as param[$ne]= are interpreted as query logic, defeating authentication.

**How it's exploited:** An attacker swaps a value for an always-matching operator to bypass login as another user, or uses $regex / $where tautologies to exfiltrate records, confirmed via auth bypass, boolean differential, or injected delay.

**Fix:** Cast input to the expected scalar type, reject objects where strings are expected, and use parameterized queries so user data cannot supply operators.`

	ModuleConfirmation = "Confirmed when NoSQL operator injection causes authentication bypass, data exfiltration, or measurable behavioral change"
	// All detection paths here are behavioral inferences (status transition,
	// boolean differential, body growth, time delay) rather than direct proof of
	// query control, so every finding is reported High/Tentative — a high-impact
	// lead to verify, not a confirmed injection.
	ModuleSeverity   = severity.High
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"injection", "sqli", "moderate"}
)
