package django_browsable_api_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "django-browsable-api-exposure"
	ModuleName  = "Django Browsable API Exposure"
	ModuleShort = "Detects DRF browsable API by requesting endpoints with Accept: text/html"
)

var (
	ModuleDesc = `**What it means:** An isolated credential-free request returned HTML with both a Django REST Framework anchor and browsable-interface structure, while two nonexistent siblings failed the same check.

**How it's exploited:** Attackers can use the interface to understand reachable API behavior. Its presence alone does not prove protected data access, a write action, or missing authorization, so this remains an observation.

**Fix:** Disable the browsable renderer in production by setting DEFAULT_RENDERER_CLASSES to serve only JSONRenderer.`

	ModuleConfirmation = "Observed when a credential-free HTML response satisfies grouped DRF/interface markers and multi-round sibling catch-all controls"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"django", "python", "info-disclosure", "probe", "light"}
)
