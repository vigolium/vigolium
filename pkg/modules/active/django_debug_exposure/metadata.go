package django_debug_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-debug-exposure"
	ModuleName  = "Django Debug Exposure"
	ModuleShort = "Triggers errors to detect Django DEBUG=True information disclosure"
)

var (
	ModuleDesc = `## Description
Triggers errors to detect Django applications running with DEBUG=True. When
enabled, Django displays detailed error pages containing settings, URL
patterns, stack traces, and environment variables. This module sends requests
designed to trigger 404 and 500 error pages that reveal debug information.

## Notes
- Runs once per host to avoid redundant probing
- Sends a request to a random non-existent path to trigger a Django debug 404 page
- Sends a malformed JSON POST to trigger a 500 error with stack trace
- Validates responses with Django-specific debug page markers

## References
- https://docs.djangoproject.com/en/stable/ref/settings/#debug`

	ModuleConfirmation = "Confirmed when error responses contain Django debug page markers indicating DEBUG=True"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "misconfiguration", "info-disclosure", "moderate"}
)
