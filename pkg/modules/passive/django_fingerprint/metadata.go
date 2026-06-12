package django_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-fingerprint"
	ModuleName  = "Django Fingerprint"
	ModuleShort = "Identifies Django installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The application is built on the Django (Python) web framework, identified passively from default CSRF and session cookies (csrftoken, sessionid), the csrfmiddlewaretoken hidden form field, Django admin or "powered by Django" references, the X-Frame-Options: DENY default, and Django error strings. Detection requires 2 or more independent signals to limit false positives. This is informational technology fingerprinting, not a vulnerability on its own. If a Django error page (ImproperlyConfigured or OperationalError) is observed, the finding also notes a debug error page is exposed, which can leak settings, file paths, and stack traces.

**How it's exploited:** Knowing the target runs Django lets an attacker narrow attack surface and focus on framework-specific weaknesses, such as known CVEs in the detected Django/Python versions, default admin paths, insecure SECRET_KEY usage, and template or deserialization issues. An exposed debug error page can directly reveal configuration, environment variables, and internal paths that aid further attacks.

**Fix:** Disable DEBUG in production, suppress framework and version banners, and keep Django patched to a supported release.`

	ModuleConfirmation = "Confirmed when 2+ independent Django-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"django", "python", "fingerprint", "light"}
)
