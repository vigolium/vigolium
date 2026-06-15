package php_generic_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-generic-fingerprint"
	ModuleName  = "PHP Generic Fingerprint"
	ModuleShort = "Identifies standalone PHP installations from server headers and session cookies"
)

var (
	ModuleDesc = `**What it means:** The server reveals the application is built on PHP, sometimes the exact version, through response headers, the PHPSESSID cookie, or .php URLs. An informational fingerprint that discloses backend technology aiding an attacker.

**How it's exploited:** Knowing the platform narrows the attack surface to PHP-specific weaknesses (local file inclusion, deserialization, type-juggling). When X-Powered-By leaks a precise version such as PHP/8.2.1, an attacker looks up CVEs for that exact build.

**Fix:** Set expose_php = Off in php.ini, remove or rewrite the X-Powered-By header at the web server or proxy, and rename the PHPSESSID cookie.`

	ModuleConfirmation = "Confirmed when an X-Powered-By PHP header or PHPSESSID cookie is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"php", "fingerprint", "light"}
)
