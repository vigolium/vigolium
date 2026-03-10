package laravel_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "laravel-sensitive-files"
	ModuleName  = "Laravel Sensitive Files"
	ModuleShort = "Detects Laravel-specific sensitive files: PHPUnit config, SQLite DB, storage internals, eval-stdin, and wrong document root"
)

var (
	ModuleDesc = `## Description
Probes for Laravel-specific sensitive files not covered by generic file discovery
modules: PHPUnit configuration (phpunit.xml), exposed SQLite databases, storage
framework internals (sessions, views, cache), vendor PHPUnit eval-stdin.php
(CVE-2017-9841), and wrong document root indicators (artisan, server.php,
routes/web.php, config/app.php, bootstrap/app.php).

## Notes
- Runs once per host to avoid redundant probing
- Complements the generic sensitive_file_discovery and php_composer_exposure modules
- Validates responses with content markers and anti-markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- Wrong document root detection is critical severity

## References
- https://laravel.com/docs/structure
- https://nvd.nist.gov/vuln/detail/CVE-2017-9841
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed Laravel file paths return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"laravel", "php", "sensitive-file", "probe", "light"}
)
