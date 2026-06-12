package django_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-admin-exposure"
	ModuleName  = "Django Admin Exposure"
	ModuleShort = "Probes for exposed Django admin panel and login page"
)

var (
	ModuleDesc = `**What it means:** The target's Django admin interface is reachable from the internet. The scanner requested the default Django admin paths (/admin/ and /admin/login/) and got a 200 response containing Django admin markers such as "Django administration", the id_username/id_password login fields, and a CSRF token, confirming the built-in admin panel and its login form are publicly exposed. This admin interface normally grants full create, read, update, and delete access to the application's data models, so it is sensitive attack surface that should not be openly reachable.

**How it's exploited:** With the login page exposed, an attacker can run credential-stuffing or brute-force attacks against admin accounts, and any weak, default, or leaked credentials yield a session with full control over the application's data. The visible panel also confirms the stack is Django, helping attackers target framework-specific weaknesses.

**Fix:** Restrict access to the admin path to trusted networks or VPN, move it off the default URL, and enforce strong unique credentials with multi-factor authentication.`

	ModuleConfirmation = "Confirmed when admin endpoints return 200 with expected Django admin-specific markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "info-disclosure", "probe", "light"}
)
