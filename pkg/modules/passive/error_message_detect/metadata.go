package error_message_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "error-message-detect"
	ModuleName  = "Error Message Detect"
	ModuleShort = "Detects interesting error messages in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The response body contains a verbose error, stack trace, or debug page that should not reach clients. This passively matches known patterns from frameworks and databases (Apache, ASP.NET, Java, PHP, Node.js, SQL engines). An information-disclosure signal, not a confirmed vulnerability.

**How it's exploited:** Leaked errors give an attacker free reconnaissance such as framework versions, internal file paths, and SQL fragments. A SQL error here is often the visible side effect of an underlying SQL injection worth probing.

**Fix:** Disable debug mode in production and return generic error pages, logging stack traces and database errors server-side only.`

	ModuleConfirmation = "Confirmed when response body contains recognizable error messages or stack traces from known frameworks"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
