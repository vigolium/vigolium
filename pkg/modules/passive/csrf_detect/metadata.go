package csrf_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csrf-detect"
	ModuleName  = "CSRF Detection"
	ModuleShort = "Flags state-changing requests missing anti-CSRF protections"
)

var (
	ModuleDesc = `**What it means:** A state-changing request (POST, PUT, DELETE, PATCH) carries a session cookie but no anti-CSRF defense: no token parameter, no custom header (X-CSRF-Token, X-Requested-With), and no SameSite=Strict/Lax cookie. Only requests forgeable cross-site are flagged, so Bearer-token APIs are skipped.

**How it's exploited:** An attacker hosts a page that auto-submits a hidden form to this endpoint. A signed-in victim who visits has their cookie replayed and the unprotected action runs - changing settings or transferring funds.

**Fix:** Require a per-session anti-CSRF token (or a server-validated custom header) on every state-changing request, and set SameSite on session cookies.`

	ModuleConfirmation = "Indicated when a state-changing request lacks CSRF token parameters, custom anti-CSRF headers, and SameSite cookie attributes"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"csrf", "session", "light"}
)
