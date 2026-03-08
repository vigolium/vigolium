package django_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-admin-exposure"
	ModuleName  = "Django Admin Exposure"
	ModuleShort = "Probes for exposed Django admin panel and login page"
)

var (
	ModuleDesc = `## Description
Probes for exposed Django admin panel. Django ships with a built-in admin
interface at /admin/ that provides full CRUD access to the application's data
models. An exposed admin panel increases attack surface and may allow brute
force or credential stuffing attacks against the admin login.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with Django admin-specific markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- Admin index reported as medium severity; login page confirms admin is installed

## References
- https://docs.djangoproject.com/en/stable/ref/contrib/admin/`

	ModuleConfirmation = "Confirmed when admin endpoints return 200 with expected Django admin-specific markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "info-disclosure", "probe", "light"}
)
