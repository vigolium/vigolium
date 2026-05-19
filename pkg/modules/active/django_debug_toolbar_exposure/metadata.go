package django_debug_toolbar_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-debug-toolbar-exposure"
	ModuleName  = "Django Debug Toolbar Exposure"
	ModuleShort = "Detects exposed django-debug-toolbar panels and render endpoints"
)

var (
	ModuleDesc = `## Description
Probes for exposed django-debug-toolbar endpoints. When debug toolbar is left
enabled in production, it exposes internal application state including SQL queries,
template context, signal handlers, cache operations, and profiling data.

## Notes
- Runs once per host to avoid redundant probing
- Validates responses with content markers to reduce false positives
- Fingerprints 404 responses to detect custom error pages
- DJ-06: django-debug-toolbar detection

## References
- https://django-debug-toolbar.readthedocs.io/`

	ModuleConfirmation = "Confirmed when debug toolbar endpoints return 200 with expected django-debug-toolbar markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "misconfiguration", "info-disclosure", "light"}
)
