package jsonp_callback

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jsonp-callback"
	ModuleName  = "JSONP Callback Injection"
	ModuleShort = "Detects JSONP endpoints that allow cross-origin data theft via callback injection"
)

var (
	ModuleDesc = `**What it means:** The endpoint returns a valid JSON object or array inside a JavaScript callback. Two fresh callback names distinguish dynamic JSONP support from a fixed function call or generic reflection.

**How it's exploited:** Public JSONP is often intentional. Sensitive values become a candidate only in a browser-executable response. A finding additionally requires a known cross-site session cookie and repeated credential-free controls that cannot retrieve the same sensitive fields.

**Fix:** Do not serve sensitive data as JSONP; return plain JSON with a controlled CORS policy and reject untrusted callbacks.`

	ModuleConfirmation = "Requires exact fresh callback wrappers around valid JSON twice; credentialed findings also require executable MIME behavior, a cross-site session cookie, and two anonymous negative controls"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "info-disclosure", "moderate"}
)
