package laravel_devtool_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-devtool-exposure"
	ModuleName  = "Laravel Developer Tool Exposure"
	ModuleShort = "Detects exposed Laravel developer tools: Web Tinker, Clockwork, Pulse, and Log Viewer"
)

var (
	ModuleDesc = `**What it means:** A Laravel app exposes a local-only developer tool, matched at a known path (/tinker, /__clockwork/latest, /pulse, /log-viewer). Severity varies: Web Tinker Critical, Clockwork and Log Viewer High, Pulse Medium.

**How it's exploited:** An exposed Web Tinker lets an attacker run arbitrary PHP in its console for full remote code execution. Clockwork and Log Viewer leak SQL queries, routes, request data, stack traces, and logs that often contain credentials, while Pulse reveals server metrics.

**Fix:** Disable these packages in production or restrict their routes to authenticated internal access, and ensure APP_DEBUG is false.`

	ModuleConfirmation = "Confirmed when developer tool endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "misconfiguration", "info-disclosure", "light"}
)
