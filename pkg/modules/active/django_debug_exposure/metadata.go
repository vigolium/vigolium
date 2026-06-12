package django_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-debug-exposure"
	ModuleName  = "Django Debug Exposure"
	ModuleShort = "Triggers errors to detect Django DEBUG=True information disclosure"
)

var (
	ModuleDesc = `**What it means:** The target is a Django application running in production with DEBUG=True. When debug mode is on, Django returns verbose error pages that expose the configured URL patterns, settings, stack traces, local variable values, and environment details. This is a serious information-disclosure misconfiguration that hands attackers an internal map of the application.

**How it's exploited:** An attacker requests a non-existent path or sends malformed input to trigger Django's debug 404/500 pages, then reads the leaked URL routes, installed apps, framework version, file paths, and frequently the SECRET_KEY, database credentials, or other settings printed in the traceback. That disclosed material is used to forge sessions, target version-specific vulnerabilities, and pivot deeper into the stack.

**Fix:** Set DEBUG=False in production settings and configure proper ALLOWED_HOSTS and custom error pages so internal details are never rendered to clients.`

	ModuleConfirmation = "Confirmed when error responses contain Django debug page markers indicating DEBUG=True"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "misconfiguration", "info-disclosure", "moderate"}
)
