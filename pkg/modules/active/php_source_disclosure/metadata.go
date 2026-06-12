package php_source_disclosure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php-source-disclosure"
	ModuleName  = "PHP Source Disclosure"
	ModuleShort = "Detects PHP source code disclosure via .phps handlers, misconfigured extensions, and static file serving"
)

var (
	ModuleDesc = `**What it means:** The web server returns raw or syntax-highlighted PHP source code instead of executing it. This happens through .phps highlight handlers, PHP files served as plaintext due to a broken handler mapping, accessible alternate extensions (.phtml, .php5, .php7), or .inc include files served as static content. The module probes common paths (config.php, wp-config.php, db.inc, and similar) and confirms a hit only when the response is HTTP 200, differs from the host's 404 fingerprint, and contains real PHP source markers such as the opening PHP tag.

**How it's exploited:** An attacker reads the leaked source in a browser to recover hardcoded database credentials, API keys, and connection strings (especially from config and .inc files), and to study application logic for further attacks like authentication bypass or injection. Exposed wp-config.php can hand over full database access.

**Fix:** Configure the web server to execute every PHP-related extension and never serve .php, .phps, .phtml, or .inc files as static or highlighted content, and move secrets out of webroot-readable files.`

	ModuleConfirmation = "Confirmed when probed endpoints return PHP source code markers in the response body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"php", "info-disclosure", "file-exposure", "light"}
)
