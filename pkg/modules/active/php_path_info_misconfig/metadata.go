package php_path_info_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-path-info-misconfig"
	ModuleName  = "PHP PATH_INFO Misconfiguration"
	ModuleShort = "Detects cgi.fix_pathinfo routing ambiguity allowing script path manipulation"
)

var (
	ModuleDesc = `**What it means:** The server runs PHP with cgi.fix_pathinfo=1, so requests like /index.php/anything/here pass the trailing PATH_INFO to a real script instead of being rejected. The scanner confirmed a valid 200 differing from the 404 fingerprint and a catch-all control.

**How it's exploited:** An attacker appends arbitrary segments to a valid endpoint (for example /index.php/admin) to slip past path-based access controls, WAF rules, or routing checks, and on classic Nginx-plus-PHP-FPM setups can coerce an uploaded file to execute.

**Fix:** Set cgi.fix_pathinfo=0 so only existing .php files reach the handler.`

	ModuleConfirmation = "Confirmed when PATH_INFO requests return a valid 200 that differs from both the random-path 404 fingerprint and a random script-shaped catch-all control, ruling out blanket SPA/rewrite handlers that serve a generic body for any path"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "misconfiguration", "light"}
)
