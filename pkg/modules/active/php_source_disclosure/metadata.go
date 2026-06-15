package php_source_disclosure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-source-disclosure"
	ModuleName  = "PHP Source Disclosure"
	ModuleShort = "Detects PHP source code disclosure via .phps handlers, misconfigured extensions, and static file serving"
)

var (
	ModuleDesc = `**What it means:** The web server returns raw or syntax-highlighted PHP source instead of executing it - via .phps handlers, a broken handler mapping, accessible alternate extensions (.phtml, .php5), or .inc files served statically. The module probes paths like config.php and wp-config.php, confirmed by PHP source markers.

**How it's exploited:** An attacker reads the leaked source to recover hardcoded database credentials, API keys, and connection strings. Exposed wp-config.php hands over full database access.

**Fix:** Configure the server to execute every PHP-related extension, never serve .php, .phps, .phtml, or .inc statically.`

	ModuleConfirmation = "Confirmed when probed endpoints return PHP source code markers in the response body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "info-disclosure", "file-exposure", "light"}
)
