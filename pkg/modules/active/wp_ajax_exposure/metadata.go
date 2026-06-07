package wp_ajax_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-ajax-exposure"
	ModuleName  = "WordPress AJAX Action Exposure"
	ModuleShort = "Detects publicly accessible WordPress AJAX actions from plugins with known vulnerabilities"
)

var (
	ModuleDesc = `## Description
Probes for commonly vulnerable WordPress AJAX actions registered via
wp_ajax_nopriv_* that should not be accessible to unauthenticated users.
These are among the most frequently exploited WordPress plugin vulnerabilities.

## Notes
- Runs once per host
- Tests known vulnerable AJAX action names from popular plugins
- Sends POST requests to /wp-admin/admin-ajax.php with action parameter
- Validates responses to distinguish real handlers from WordPress default "0" response
- Requires plugin/action-specific markers in the response body so generic
  CDN/WAF/SPA error pages are not mistaken for an exposed handler
- Does not attempt exploitation, only confirms action handler existence

## References
- https://developer.wordpress.org/plugins/javascript/ajax/
- https://www.wordfence.com/threat-intel/vulnerabilities`

	ModuleConfirmation = "Confirmed when admin-ajax.php returns a non-default response that contains plugin/action-specific markers for a known vulnerable action name"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "cms", "php", "misconfiguration", "light"}
)
