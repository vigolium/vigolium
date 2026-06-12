package clickjacking_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "clickjacking-detect"
	ModuleName  = "Clickjacking (UI Redress)"
	ModuleShort = "Detects framable pages with sensitive/interactive content vulnerable to clickjacking"
)

var (
	ModuleDesc = `**What it means:** This HTML page can be loaded inside a cross-origin iframe because it lacks effective anti-framing protection (no restrictive CSP frame-ancestors and no DENY/SAMEORIGIN X-Frame-Options), and it carries content worth hijacking: a credential/password form, an authenticated session, or a form posting to a sensitive or state-changing endpoint. That combination makes the page vulnerable to clickjacking (UI redress).

**How it's exploited:** An attacker frames the target page in an invisible, transparent iframe overlaid on a decoy site, then lures a logged-in victim into clicking decoy elements that actually land on the framed page's buttons or fields. This can trigger unintended state-changing actions (account changes, transfers, deletions, grants) or trick users into submitting credentials, all under the victim's authenticated session. When the session cookie is SameSite=Strict/Lax the frame loads unauthenticated, so the finding is downgraded.

**Fix:** Send Content-Security-Policy: frame-ancestors 'none' (or 'self') and X-Frame-Options: DENY/SAMEORIGIN on this page.`

	ModuleConfirmation = "Confirmed when a 200 OK HTML page lacks effective frame-ancestors/X-Frame-Options protection and carries sensitive or authenticated interactive content"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"clickjacking", "ui-redress", "header-security", "misconfiguration", "light"}
)
