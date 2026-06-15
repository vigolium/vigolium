package django_debug_toolbar_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-debug-toolbar-exposure"
	ModuleName  = "Django Debug Toolbar Exposure"
	ModuleShort = "Detects exposed django-debug-toolbar panels and render endpoints"
)

var (
	ModuleDesc = `**What it means:** The django-debug-toolbar is reachable on what should be a production deployment, confirmed via /__debug__/ and /__debug__/render_panel/ matching toolbar markers. This development-only component surfaces internal application state and should never be live.

**How it's exploited:** An attacker browsing these endpoints reads executed SQL queries, request and template context, settings, installed apps, and profiling data. This leaks database schema, internal paths, and dependency versions, mapping follow-on SQL injection, authentication, or configuration attacks.

**Fix:** Set DEBUG=False, remove debug_toolbar from INSTALLED_APPS and its URL include in production, and restrict access via INTERNAL_IPS or the SHOW_TOOLBAR_CALLBACK.`

	ModuleConfirmation = "Confirmed when debug toolbar endpoints return 200 with expected django-debug-toolbar markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "misconfiguration", "info-disclosure", "light"}
)
