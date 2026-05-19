package laravel_devtool_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-devtool-exposure"
	ModuleName  = "Laravel Developer Tool Exposure"
	ModuleShort = "Detects exposed Laravel developer tools: Web Tinker, Clockwork, Pulse, and Log Viewer"
)

var (
	ModuleDesc = `## Description
Probes for exposed Laravel developer tools that should not be accessible in
production: Web Tinker (interactive PHP console), Clockwork (profiling tool),
Laravel Pulse (monitoring dashboard), and Log Viewer. These tools can expose
sensitive data such as SQL queries, routes, timings, logs, and may allow
arbitrary code execution.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- Web Tinker is critical severity due to potential code execution

## References
- https://github.com/spatie/laravel-web-tinker
- https://github.com/itsgoingd/clockwork
- https://laravel.com/docs/pulse
- https://github.com/opcodesio/log-viewer`

	ModuleConfirmation = "Confirmed when developer tool endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "misconfiguration", "info-disclosure", "light"}
)
