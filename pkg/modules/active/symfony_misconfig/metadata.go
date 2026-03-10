package symfony_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "symfony-misconfig"
	ModuleName  = "Symfony Misconfiguration"
	ModuleShort = "Detects exposed Symfony profiler, debug toolbar, dev front controller, and configuration leaks"
)

var (
	ModuleDesc = `## Description
Probes for Symfony framework-specific misconfigurations: web profiler/debug toolbar
accessible in production, dev front controller (app_dev.php) exposed, debug logs,
and exposed configuration files.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Checks for X-Debug-Token and X-Debug-Token-Link response headers
- Fingerprints 404 responses to detect custom error pages

## References
- https://symfony.com/doc/current/reference/configuration/framework.html
- https://symfony.com/doc/current/profiler.html
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed Symfony endpoints return 200 with expected framework-specific markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"symfony", "php", "misconfiguration", "info-disclosure", "light"}
)
