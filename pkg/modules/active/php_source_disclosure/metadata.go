package php_source_disclosure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-source-disclosure"
	ModuleName  = "PHP Source Disclosure"
	ModuleShort = "Detects PHP source code disclosure via .phps handlers, misconfigured extensions, and static file serving"
)

var (
	ModuleDesc = `## Description
Probes for PHP source code disclosure caused by misconfigured web servers: .phps
highlight handlers that expose syntax-highlighted source, alternate PHP extensions
(.phtml, .php5, .php7) that may serve source as plaintext, and PHP files served
as static content due to handler misconfiguration.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with PHP source code markers
- Detects both highlighted source and raw PHP code exposure
- Fingerprints 404 responses to detect custom error pages

## References
- https://www.php.net/manual/en/security.hiding.php
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed endpoints return PHP source code markers in the response body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"php", "info-disclosure", "file-exposure", "light"}
)
