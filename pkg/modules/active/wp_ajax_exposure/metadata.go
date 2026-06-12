package wp_ajax_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-ajax-exposure"
	ModuleName  = "WordPress AJAX Action Exposure"
	ModuleShort = "Detects publicly accessible WordPress AJAX actions from plugins with known vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** The site exposes a WordPress AJAX action (registered via wp_ajax_nopriv_*) belonging to a plugin with a known public vulnerability, and that handler responds to unauthenticated requests at /wp-admin/admin-ajax.php. Several of the matched plugins (e.g. Revolution Slider, Duplicator, WP File Manager, All-in-One WP Migration, InfiniteWP) have disclosed flaws ranging from arbitrary file download and full-site backup leakage to authentication bypass and remote code execution, so an exposed handler is a high-value attack surface.

**How it's exploited:** An attacker maps the WordPress and plugin version from the confirmed action, then sends the documented exploit POST for that specific CVE (for example downloading a full site backup, reading arbitrary files, resetting the database, or registering a privileged user) entirely without authentication. This module only confirms the handler is reachable; it does not run the exploit.

**Fix:** Update or remove the affected plugin, restrict admin-ajax actions to authenticated and authorized users, and apply a WAF rule blocking the vulnerable action names.`

	ModuleConfirmation = "Confirmed when admin-ajax.php returns a non-default response that contains plugin/action-specific markers for a known vulnerable action name"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "cms", "php", "misconfiguration", "light"}
)
