package php_generic_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-generic-fingerprint"
	ModuleName  = "PHP Generic Fingerprint"
	ModuleShort = "Identifies standalone PHP installations from server headers and session cookies"
)

var (
	ModuleDesc = `## Description
Passively identifies PHP installations not already covered by a framework
fingerprint (WordPress, Laravel, Drupal, Joomla, Symfony). Catches standalone
PHP applications, custom PHP backends, and legacy sites via the X-Powered-By
header, PHPSESSID session cookie, and .php URL extensions.

## Signals
- X-Powered-By header containing PHP/<version>
- Set-Cookie: PHPSESSID=
- URL path ending in .php (weak — requires another signal)

## Notes
- Passive only: does not send any HTTP requests
- Deduplicates by host
- Publishes "php" to the tech registry so php-tagged active modules run

## References
- https://www.php.net/`

	ModuleConfirmation = "Confirmed when an X-Powered-By PHP header or PHPSESSID cookie is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"php", "fingerprint", "light"}
)
