package django_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-admin-exposure"
	ModuleName  = "Django Admin Exposure"
	ModuleShort = "Probes for exposed Django admin panel and login page"
)

var (
	ModuleDesc = `**What it means:** The Django admin interface is reachable from the internet. The default paths (/admin/ and /admin/login/) returned 200 with admin markers, confirming the built-in panel and login form are publicly exposed. This interface normally grants full read/write access to data models.

**How it's exploited:** An attacker runs credential-stuffing or brute-force against admin accounts; any weak, default, or leaked credentials yield a session with full control over the data. The panel also confirms the Django stack.

**Fix:** Restrict the admin path to trusted networks or VPN, move it off the default URL, and enforce strong credentials with multi-factor authentication.`

	ModuleConfirmation = "Confirmed when admin endpoints return 200 with expected Django admin-specific markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "info-disclosure", "probe", "light"}
)
