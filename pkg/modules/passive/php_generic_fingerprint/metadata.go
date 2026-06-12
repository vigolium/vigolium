package php_generic_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-generic-fingerprint"
	ModuleName  = "PHP Generic Fingerprint"
	ModuleShort = "Identifies standalone PHP installations from server headers and session cookies"
)

var (
	ModuleDesc = `**What it means:** The server reveals that the application is built on PHP, and sometimes the exact PHP version, through response headers, the PHPSESSID session cookie, or .php URLs. This is an informational fingerprint, not a vulnerability, but it discloses backend technology details that aid an attacker.

**How it's exploited:** Knowing the platform lets an attacker narrow their attack surface to PHP-specific weaknesses (local file inclusion, deserialization, type-juggling). When the X-Powered-By header also leaks a precise version such as PHP/8.2.1, the attacker can look up published CVEs for that exact build and target known, version-specific exploits instead of probing blindly.

**Fix:** Suppress technology disclosure by setting expose_php = Off in php.ini, removing or rewriting the X-Powered-By header at the web server or proxy, and renaming the PHPSESSID session cookie.`

	ModuleConfirmation = "Confirmed when an X-Powered-By PHP header or PHPSESSID cookie is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"php", "fingerprint", "light"}
)
