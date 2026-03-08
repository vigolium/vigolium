package django_browsable_api_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-browsable-api-exposure"
	ModuleName  = "Django Browsable API Exposure"
	ModuleShort = "Detects DRF browsable API by requesting endpoints with Accept: text/html"
)

var (
	ModuleDesc = `## Description
Detects Django REST Framework browsable API exposure by re-requesting endpoints
with Accept: text/html. When the browsable API is enabled in production, it
provides an interactive HTML interface that reveals API schema, available actions,
filter options, and authentication requirements.

## Notes
- Runs once per host to avoid redundant probing
- Re-requests the original URL with Accept: text/html header
- Also probes /api/ with Accept: text/html
- DJ-07: DRF browsable API detection

## References
- https://www.django-rest-framework.org/topics/browsable-api/`

	ModuleConfirmation = "Confirmed when endpoints return HTML containing DRF browsable API markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "info-disclosure", "probe", "light"}
)
