package nextjs_draft_mode_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-draft-mode-exposure"
	ModuleName  = "Next.js Draft Mode Exposure"
	ModuleShort = "Detects insecure or unprotected Next.js Draft/Preview Mode endpoints"
)

var (
	ModuleDesc = `**What it means:** A Next.js Draft/Preview Mode endpoint enables draft mode without a valid secret, exposing embargoed, internal, or unpublished CMS content to anonymous visitors.

**How it's exploited:** An attacker visits a draft route (for example /api/draft, /api/preview, /api/enable-preview) with no secret to obtain the __prerender_bypass or __next_preview_data bypass cookie, then browses the site to read draft and preview-only content meant to stay hidden.

**Fix:** Require a strong, unguessable secret on every draft/preview enabling endpoint and reject requests whose secret does not match, per the Next.js Draft Mode documentation.`

	ModuleConfirmation = "Confirmed when a draft/preview endpoint sets bypass cookies without a valid secret"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "misconfiguration", "light"}
)
