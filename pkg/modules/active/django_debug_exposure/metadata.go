package django_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-debug-exposure"
	ModuleName  = "Django Debug Exposure"
	ModuleShort = "Triggers errors to detect Django DEBUG=True information disclosure"
)

var (
	ModuleDesc = `**What it means:** A Django application is running in production with DEBUG=True, returning verbose error pages that expose URL patterns, settings, stack traces, and environment details - handing attackers an internal map of the application.

**How it's exploited:** An attacker triggers Django's debug 404/500 pages with a bad path or malformed input, then reads the leaked URL routes, installed apps, framework version, and frequently the SECRET_KEY or database credentials - used to forge sessions and pivot deeper.

**Fix:** Set DEBUG=False in production and configure proper ALLOWED_HOSTS and custom error pages so internal details are never rendered to clients.`

	ModuleConfirmation = "Confirmed when error responses contain Django debug page markers indicating DEBUG=True"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "misconfiguration", "info-disclosure", "moderate"}
)
