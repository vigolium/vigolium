package django_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-fingerprint"
	ModuleName  = "Django Fingerprint"
	ModuleShort = "Identifies Django installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `**What it means:** The app runs the Django (Python) framework, identified passively from default cookies (csrftoken, sessionid), the csrfmiddlewaretoken form field, admin references, and error strings. Two or more signals are required to limit false positives. Informational fingerprinting. An observed Django error page is also noted as an exposed debug page.

**How it's exploited:** Knowing the target runs Django lets an attacker focus on framework-specific weaknesses - version CVEs, default admin paths, insecure SECRET_KEY use, deserialization issues. A debug page reveals config and paths.

**Fix:** Disable DEBUG in production, suppress framework and version banners, and keep Django patched.`

	ModuleConfirmation = "Confirmed when 2+ independent Django-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"django", "python", "fingerprint", "light"}
)
