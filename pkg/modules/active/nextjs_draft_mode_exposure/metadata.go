package nextjs_draft_mode_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-draft-mode-exposure"
	ModuleName  = "Next.js Draft Mode Exposure"
	ModuleShort = "Detects insecure or unprotected Next.js Draft/Preview Mode endpoints"
)

var (
	ModuleDesc = `**What it means:** A Next.js endpoint issued a live preview cookie without a valid secret. The cookie is a candidate; repeated stable content that differs from cookie-free controls confirms exposure.

**How it's exploited:** An attacker calls the draft route without its secret, receives a preview cookie, and browses unpublished content.

**Fix:** Require a strong secret on every draft-enabling endpoint, reject mismatches, and ensure exit routes only delete preview cookies.`

	ModuleConfirmation = "Candidate on a live non-deletion preview cookie; confirmed only by a stable cookie-versus-no-cookie content differential on a follow-up route"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "misconfiguration", "light"}
)
