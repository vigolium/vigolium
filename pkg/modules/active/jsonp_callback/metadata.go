package jsonp_callback

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jsonp-callback"
	ModuleName  = "JSONP Callback Injection"
	ModuleShort = "Detects JSONP endpoints that allow cross-origin data theft via callback injection"
)

var (
	ModuleDesc = `**What it means:** The endpoint serves data as JSONP, wrapping its JSON in a function call whose name comes from a request parameter. A script tag ignores same-origin policy, so any site can read this data. Severity rises to High when sensitive fields appear.

**How it's exploited:** An attacker hosts a page that loads this URL in a script tag and defines the callback; a logged-in victim's cookies are sent automatically and the attacker reads the returned data cross-origin (XSSI).

**Fix:** Do not serve sensitive data as JSONP; return plain JSON with a controlled CORS policy and reject untrusted callbacks.`

	ModuleConfirmation = "Confirmed when injecting a callback parameter causes the response to be wrapped in the specified function call"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "info-disclosure", "moderate"}
)
