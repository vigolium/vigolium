package django_browsable_api_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-browsable-api-exposure"
	ModuleName  = "Django Browsable API Exposure"
	ModuleShort = "Detects DRF browsable API by requesting endpoints with Accept: text/html"
)

var (
	ModuleDesc = `**What it means:** The Django REST Framework browsable API is enabled and reachable in production. This module re-requests the endpoint (and the /api/ root) with an Accept: text/html header and confirms a 200 response containing DRF browsable-API markers, meaning the framework serves an interactive HTML interface that exposes API structure, available HTTP actions, filter and pagination options, and authentication requirements. It is an information-disclosure finding, not a direct compromise.

**How it's exploited:** An attacker browses the rendered interface to map the API's endpoints, methods, serializer fields, and required parameters without guesswork, then uses that schema knowledge to craft targeted requests against the underlying API (for example probing write actions or filterable fields). The interactive forms can also make it easier to exercise endpoints by hand, accelerating discovery of authorization or input-validation weaknesses.

**Fix:** Disable the browsable API renderer in production by configuring DEFAULT_RENDERER_CLASSES to serve only JSONRenderer (drop BrowsableAPIRenderer).`

	ModuleConfirmation = "Confirmed when endpoints return HTML containing DRF browsable API markers"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "info-disclosure", "probe", "light"}
)
