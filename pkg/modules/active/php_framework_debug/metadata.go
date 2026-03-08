package php_framework_debug

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-php-framework-debug"
	ModuleName  = "PHP Framework Debug Exposure"
	ModuleShort = "Detects exposed debug endpoints for Yii, CodeIgniter, CakePHP, and other PHP frameworks"
)

var (
	ModuleDesc = `## Description
Probes for debug and development endpoints specific to PHP frameworks beyond
Laravel and Symfony: Yii debug module and Gii code generator, CodeIgniter
user guide and profiler output, CakePHP debug kit, and common PHP framework
debug patterns.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Covers Yii, CodeIgniter, CakePHP, and Slim frameworks
- Fingerprints 404 responses to detect custom error pages

## References
- https://www.yiiframework.com/doc/guide/2.0/en/tool-debugger
- https://codeigniter.com/user_guide/
- https://book.cakephp.org/4/en/debug-kit.html
- https://owasp.org/www-project-web-security-testing-guide/`

	ModuleConfirmation = "Confirmed when probed framework debug endpoints return 200 with expected content markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"php", "misconfiguration", "info-disclosure", "light"}
)
