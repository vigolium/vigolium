package php_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-debug-exposure"
	ModuleName  = "PHP Debug Exposure"
	ModuleShort = "Detects exposed phpinfo pages, PHP-FPM status endpoints, and phpMyAdmin instances"
)

var (
	ModuleDesc = `## Description
Probes for PHP-specific debug and administration endpoints that should not be
publicly accessible: phpinfo() pages at common paths, PHP-FPM status/ping
endpoints, and phpMyAdmin installations.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Complements sensitive_file_discovery with additional PHP-specific paths
- Fingerprints 404 responses to detect custom error pages

## References
- https://www.php.net/manual/en/function.phpinfo.php
- https://www.php.net/manual/en/fpm.status.php
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed PHP debug endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"php", "misconfiguration", "info-disclosure", "light"}
)
