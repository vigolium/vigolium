package laravel_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-misconfig"
	ModuleName  = "Laravel Misconfiguration"
	ModuleShort = "Detects Laravel debug mode, exposed debugbar, application logs, and configuration leaks"
)

var (
	ModuleDesc = `## Description
Probes for Laravel framework-specific misconfigurations: debug mode enabled with
Ignition/Whoops error pages, exposed debugbar endpoints leaking SQL queries and
routes, accessible application logs with stack traces and secrets, and exposed
Telescope debugging dashboard.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- Debug mode detection triggers a deliberate error to check for Ignition/Whoops

## References
- https://laravel.com/docs/configuration
- https://flareapp.io/docs/ignition-for-laravel/introduction
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed Laravel endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "misconfiguration", "info-disclosure", "moderate"}
)
