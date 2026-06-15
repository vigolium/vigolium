package wp_ajax_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-ajax-exposure"
	ModuleName  = "WordPress AJAX Action Exposure"
	ModuleShort = "Detects publicly accessible WordPress AJAX actions from plugins with known vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** The site exposes a WordPress AJAX action (registered via wp_ajax_nopriv_*) from a plugin with a known vulnerability, answering unauthenticated requests at /wp-admin/admin-ajax.php. Matched plugins (Revolution Slider, Duplicator, WP File Manager) have flaws from file download to auth bypass and RCE.

**How it's exploited:** An attacker maps the plugin version from the confirmed action, then sends the documented exploit POST for that CVE (downloading a backup, reading files, or registering an admin) without authentication.

**Fix:** Update or remove the plugin, restrict admin-ajax actions to authorized users, and add a WAF rule blocking the vulnerable action names.`

	ModuleConfirmation = "Confirmed when admin-ajax.php returns a non-default response that contains plugin/action-specific markers for a known vulnerable action name"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "cms", "php", "misconfiguration", "light"}
)
