package clickjacking_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "clickjacking-detect"
	ModuleName  = "Clickjacking (UI Redress)"
	ModuleShort = "Detects framable pages with sensitive/interactive content vulnerable to clickjacking"
)

var (
	ModuleDesc = `**What it means:** This HTML page can load in a cross-origin iframe - it lacks effective anti-framing protection (no CSP frame-ancestors, no DENY/SAMEORIGIN X-Frame-Options) and carries content worth hijacking: a credential form, an authenticated session, or a form posting to a state-changing endpoint. That makes it vulnerable to clickjacking.

**How it's exploited:** An attacker overlays the page in an invisible iframe and lures a logged-in victim into clicking decoys that land on real buttons, triggering state-changing actions or credential entry under the victim's session. SameSite=Strict/Lax cookies downgrade it.

**Fix:** Send CSP frame-ancestors 'none' (or 'self') and X-Frame-Options: DENY/SAMEORIGIN.`

	ModuleConfirmation = "Confirmed when a 200 OK HTML page lacks effective frame-ancestors/X-Frame-Options protection and carries sensitive or authenticated interactive content"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"clickjacking", "ui-redress", "header-security", "misconfiguration", "light"}
)
