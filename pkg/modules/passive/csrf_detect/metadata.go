package csrf_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csrf-detect"
	ModuleName  = "CSRF Detection"
	ModuleShort = "Flags state-changing requests missing anti-CSRF protections"
)

var (
	ModuleDesc = `**What it means:** A state-changing request (POST, PUT, DELETE, or PATCH) carries a session cookie but has no anti-CSRF defense: no CSRF token parameter, no custom anti-CSRF header (such as X-CSRF-Token or X-Requested-With), and no SameSite=Strict or SameSite=Lax attribute on its cookies. Because the browser attaches the session cookie automatically, another website can trigger this action on behalf of a logged-in victim. This module only flags requests genuinely forgeable cross-site (simple form content type, no Authorization header, an ambient cookie present), so JSON APIs, Bearer-token APIs, and unauthenticated requests are skipped.

**How it's exploited:** An attacker hosts a page that auto-submits a hidden form to this endpoint. When a signed-in victim visits it, the browser replays their cookie and the unprotected action runs, letting the attacker change settings, transfer funds, or create accounts as the victim without their consent.

**Fix:** Require a per-session anti-CSRF token (or a custom header validated server-side) on every state-changing request, and set SameSite=Strict or Lax on session cookies.`

	ModuleConfirmation = "Indicated when a state-changing request lacks CSRF token parameters, custom anti-CSRF headers, and SameSite cookie attributes"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"csrf", "session", "light"}
)
