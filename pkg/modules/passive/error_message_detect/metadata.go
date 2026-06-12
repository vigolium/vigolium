package error_message_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "error-message-detect"
	ModuleName  = "Error Message Detect"
	ModuleShort = "Detects interesting error messages in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The response body contains a verbose error message, stack trace, or debug page that the application should not expose to clients. This module passively matches known patterns from frameworks and databases (debug pages, Apache, ASP.NET, Java, Python, PHP, Ruby, Node.js, and many SQL engines) and reports the category that was found. It is an information-disclosure signal, not a confirmed vulnerability, so it is rated Low (debug and SQL errors) to Info (other categories).

**How it's exploited:** Leaked errors hand an attacker free reconnaissance: framework and database versions, internal file paths, class and method names, and SQL fragments. This narrows attack surface, enables version-specific exploit targeting, and a SQL error surfacing here is often the visible side effect of an underlying SQL injection an attacker can then probe further.

**Fix:** Disable debug mode in production and return generic error pages, logging full stack traces and database errors server-side only.`

	ModuleConfirmation = "Confirmed when response body contains recognizable error messages or stack traces from known frameworks"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
