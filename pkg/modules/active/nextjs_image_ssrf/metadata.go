package nextjs_image_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-nextjs-image-ssrf"
	ModuleName  = "Next.js Image Optimizer SSRF"
	ModuleShort = "Detects SSRF via the Next.js image optimization endpoint"
)

var (
	ModuleDesc = `## Description
Tests the Next.js image optimization endpoint (/_next/image) for Server-Side Request
Forgery. The image optimizer accepts a URL parameter and fetches the image server-side.
If improperly configured, it can be abused to access internal resources or cloud
metadata endpoints.

## Notes
- Runs once per host on Next.js-identified targets
- First verifies /_next/image endpoint exists
- Uses OAST for out-of-band confirmation when available
- Falls back to in-band probes (AWS metadata, localhost)
- Deduplicates by host

## References
- https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps
- https://nextjs.org/docs/pages/api-reference/components/image`

	ModuleConfirmation = "Confirmed when the image optimizer fetches an attacker-controlled or internal URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"nextjs", "javascript", "ssrf", "moderate"}
)
