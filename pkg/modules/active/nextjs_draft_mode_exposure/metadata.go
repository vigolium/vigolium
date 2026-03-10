package nextjs_draft_mode_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-draft-mode-exposure"
	ModuleName  = "Next.js Draft Mode Exposure"
	ModuleShort = "Detects insecure or unprotected Next.js Draft/Preview Mode endpoints"
)

var (
	ModuleDesc = `## Description
Probes common Next.js Draft Mode and Preview Mode API endpoints for missing or weak
authentication. Draft Mode allows viewing unpublished CMS content by setting special
cookies (__prerender_bypass, __next_preview_data). If the enabling endpoint lacks
proper secret validation, attackers can access embargoed or sensitive content.

## Notes
- Runs once per host on Next.js-identified targets
- Probes common draft/preview API routes with no token and common weak tokens
- Confirms by detecting __prerender_bypass or __next_preview_data cookies in response
- Deduplicates by host

## References
- https://nextjs.org/docs/app/guides/draft-mode
- https://nextjs.org/docs/pages/building-your-application/configuring/preview-mode`

	ModuleConfirmation = "Confirmed when a draft/preview endpoint sets bypass cookies without a valid secret"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"nextjs", "javascript", "misconfiguration", "light"}
)
