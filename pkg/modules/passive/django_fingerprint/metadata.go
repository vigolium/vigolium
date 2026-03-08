package django_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-fingerprint"
	ModuleName  = "Django Fingerprint"
	ModuleShort = "Identifies Django installations from response headers, cookies, and body patterns"
)

var (
	ModuleDesc = `## Description
Passively identifies Django installations by analyzing HTTP response cookies
(csrftoken, sessionid), body patterns (csrfmiddlewaretoken hidden field,
Django-specific error strings), and default header configurations. Requires
2+ independent signals to avoid false positives.

## Notes
- Passive only: does not send any HTTP requests
- Deduplicates by host to avoid redundant processing
- Detects Django default CSRF cookie and session cookie names
- Recognizes Django error page patterns (ImproperlyConfigured, OperationalError)
- X-Frame-Options: DENY is a weak signal, only counted with another signal

## References
- https://www.djangoproject.com/`

	ModuleConfirmation = "Confirmed when 2+ independent Django-specific signals are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"django", "python", "fingerprint", "light"}
)
