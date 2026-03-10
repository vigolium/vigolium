package php_composer_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-composer-exposure"
	ModuleName  = "PHP Composer Exposure"
	ModuleShort = "Detects exposed Composer manifests, vendor directory, and PHPUnit dev endpoints"
)

var (
	ModuleDesc = `## Description
Probes for Composer dependency management artifacts that should not be publicly
accessible: composer.json and composer.lock manifests revealing exact dependency
versions, vendor directory contents, Composer installed metadata, and PHPUnit
dev endpoint that may allow remote code execution.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- PHPUnit eval-stdin.php is a known RCE vector in vulnerable versions

## References
- https://getcomposer.org/doc/
- https://blog.packagist.com/composer-lock-security/
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed Composer artifacts return 200 with expected content markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"php", "file-exposure", "info-disclosure", "light"}
)
