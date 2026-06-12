package nextjs_draft_mode_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-draft-mode-exposure"
	ModuleName  = "Next.js Draft Mode Exposure"
	ModuleShort = "Detects insecure or unprotected Next.js Draft/Preview Mode endpoints"
)

var (
	ModuleDesc = `**What it means:** A Next.js Draft Mode or Preview Mode endpoint on this site enables draft mode without requiring a valid secret. Draft mode is meant to let editors preview unpublished CMS content, so an endpoint that activates it for anyone exposes embargoed, internal, or not-yet-published content to unauthenticated visitors.

**How it's exploited:** The scanner requested common draft/preview routes (for example /api/draft, /api/preview, /api/enable-preview) with no secret and with common weak tokens, and confirmed the response set the __prerender_bypass or __next_preview_data bypass cookie. An attacker simply visits the same endpoint to obtain those cookies, then browses the site to read draft and preview-only content that should be hidden.

**Fix:** Require a strong, unguessable secret on every draft/preview enabling endpoint and reject requests whose secret does not match, following the Next.js Draft Mode and Preview Mode documentation.`

	ModuleConfirmation = "Confirmed when a draft/preview endpoint sets bypass cookies without a valid secret"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "misconfiguration", "light"}
)
