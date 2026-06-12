package django_debug_toolbar_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-debug-toolbar-exposure"
	ModuleName  = "Django Debug Toolbar Exposure"
	ModuleShort = "Detects exposed django-debug-toolbar panels and render endpoints"
)

var (
	ModuleDesc = `**What it means:** The django-debug-toolbar is reachable on this host in what should be a production deployment. The module confirmed this by requesting /__debug__/ and /__debug__/render_panel/ and matching toolbar markers (djDebug, djdt, Django Debug Toolbar, panel) after fingerprinting the site's 404 page to rule out custom error pages. The toolbar is a development-only component that surfaces internal application state and should never be live in production.
**How it's exploited:** An attacker browsing these endpoints can read executed SQL queries, request and template context, settings, installed apps, cache and signal activity, and profiling data. This leaks database schema, internal paths, framework and dependency versions, and sometimes secrets or session details, giving a clear map for follow-on SQL injection, authentication, or configuration attacks.
**Fix:** Set DEBUG=False, remove debug_toolbar from INSTALLED_APPS and its URL include in production, and restrict access via INTERNAL_IPS or the SHOW_TOOLBAR_CALLBACK.`

	ModuleConfirmation = "Confirmed when debug toolbar endpoints return 200 with expected django-debug-toolbar markers"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "misconfiguration", "info-disclosure", "light"}
)
