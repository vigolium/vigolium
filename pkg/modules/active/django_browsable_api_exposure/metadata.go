package django_browsable_api_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-browsable-api-exposure"
	ModuleName  = "Django Browsable API Exposure"
	ModuleShort = "Detects DRF browsable API by requesting endpoints with Accept: text/html"
)

var (
	ModuleDesc = `**What it means:** The Django REST Framework browsable API is enabled in production. Requesting the endpoint with Accept: text/html returned 200 with DRF markers, meaning the framework serves an interactive HTML interface exposing API structure, HTTP actions, and auth requirements. An information-disclosure finding, not a direct compromise.

**How it's exploited:** An attacker browses the rendered interface to map endpoints, methods, serializer fields, and required parameters without guesswork, then crafts targeted requests against the API, speeding discovery of authorization weaknesses.

**Fix:** Disable the browsable renderer in production by setting DEFAULT_RENDERER_CLASSES to serve only JSONRenderer.`

	ModuleConfirmation = "Confirmed when endpoints return HTML containing DRF browsable API markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "info-disclosure", "probe", "light"}
)
