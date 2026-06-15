package nextjs_image_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-image-ssrf"
	ModuleName  = "Next.js Image Optimizer SSRF"
	ModuleShort = "Detects SSRF via the Next.js image optimization endpoint"
)

var (
	ModuleDesc = `**What it means:** The Next.js image optimizer (/_next/image) fetches its url parameter server-side without restricting destinations - an SSRF flaw letting the app be coerced into requesting attacker-chosen hosts, including unreachable internal systems.

**How it's exploited:** An attacker points url at an internal address such as cloud metadata (AWS 169.254.169.254, GCP metadata.google.internal) or localhost; the server fetches and returns it. This can leak temporary credentials and instance secrets and probe internal services.

**Fix:** Restrict the optimizer to an allowlist of trusted external image domains (images.domains / remotePatterns) and block internal, private, and link-local addresses.`

	ModuleConfirmation = "Confirmed when the image optimizer fetches an attacker-controlled or internal URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "ssrf", "moderate"}
)
