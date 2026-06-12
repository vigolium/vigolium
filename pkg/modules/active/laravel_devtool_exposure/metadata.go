package laravel_devtool_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-devtool-exposure"
	ModuleName  = "Laravel Developer Tool Exposure"
	ModuleShort = "Detects exposed Laravel developer tools: Web Tinker, Clockwork, Pulse, and Log Viewer"
)

var (
	ModuleDesc = `**What it means:** A Laravel application is exposing a developer or debugging tool to the public that should only run in local development. The scanner confirmed one of these tools by requesting its known path (such as /tinker, /__clockwork/latest, /pulse, or /log-viewer) and matching framework-specific content markers in a 200 response, after fingerprinting a random 404 to rule out catch-all error pages. Severity depends on the tool: Web Tinker is Critical, Clockwork and Log Viewer are High, and Pulse is Medium.

**How it's exploited:** If Web Tinker is exposed, an attacker types arbitrary PHP into its web console and gets full remote code execution on the server. Clockwork and Log Viewer leak SQL queries, routes, request data, stack traces, and application logs that often contain credentials, tokens, and user data, while Pulse reveals performance and server metrics. Any of these aids further compromise.

**Fix:** Disable these packages in production or restrict their routes to authenticated internal access, and ensure APP_DEBUG is false.`

	ModuleConfirmation = "Confirmed when developer tool endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "misconfiguration", "info-disclosure", "light"}
)
