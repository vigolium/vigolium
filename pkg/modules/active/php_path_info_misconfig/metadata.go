package php_path_info_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-path-info-misconfig"
	ModuleName  = "PHP PATH_INFO Misconfiguration"
	ModuleShort = "Detects cgi.fix_pathinfo routing ambiguity allowing script path manipulation"
)

var (
	ModuleDesc = `**What it means:** The server runs PHP with cgi.fix_pathinfo=1, so requests like /index.php/anything/here pass the trailing PATH_INFO segment to a real PHP script instead of being rejected. The scanner confirmed this by sending PATH_INFO and encoded-slash variants (and a non-existent script path) and getting a valid 200 that differs from the site's 404 fingerprint and from a random catch-all control. This routing ambiguity weakens path-based security and, on older or misconfigured setups, has historically allowed uploaded or attacker-controlled files to be executed as PHP.

**How it's exploited:** An attacker appends arbitrary path segments to a valid PHP endpoint (for example /index.php/admin) to slip past URL- or path-based access controls, WAF rules, or routing checks, and on classic Nginx-plus-PHP-FPM misconfigurations can coerce a non-PHP file such as an upload to be executed as a script.

**Fix:** Set cgi.fix_pathinfo=0 in php.ini and configure the web server so only existing .php files are passed to the PHP-FPM/CGI handler.`

	ModuleConfirmation = "Confirmed when PATH_INFO requests return a valid 200 that differs from both the random-path 404 fingerprint and a random script-shaped catch-all control, ruling out blanket SPA/rewrite handlers that serve a generic body for any path"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "misconfiguration", "light"}
)
