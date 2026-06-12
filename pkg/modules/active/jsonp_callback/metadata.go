package jsonp_callback

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jsonp-callback"
	ModuleName  = "JSONP Callback Injection"
	ModuleShort = "Detects JSONP endpoints that allow cross-origin data theft via callback injection"
)

var (
	ModuleDesc = `**What it means:** The endpoint serves data as JSONP, wrapping its JSON payload in a JavaScript function call whose name comes from a request parameter. The scanner confirmed this either by seeing a response already wrapped in a callback, or by injecting a common callback parameter and seeing the response wrap itself in the attacker-supplied function name. Because a script tag executes regardless of the same-origin policy, any site can read this data on behalf of a logged-in victim. Severity rises to High when the response holds sensitive fields like email, password, or token.

**How it's exploited:** An attacker hosts a page that loads this URL in a script tag and defines the callback to capture the data. When a logged-in victim visits, their cookies are sent automatically and the attacker's JavaScript reads whatever the endpoint returns, stealing personal or authenticated data cross-origin (a Cross-Site Script Inclusion attack).

**Fix:** Do not serve sensitive or authenticated data as JSONP; return plain JSON with a controlled CORS policy and reject untrusted callbacks.`

	ModuleConfirmation = "Confirmed when injecting a callback parameter causes the response to be wrapped in the specified function call"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "info-disclosure", "moderate"}
)
