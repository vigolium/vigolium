package nextjs_image_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-image-ssrf"
	ModuleName  = "Next.js Image Optimizer SSRF"
	ModuleShort = "Detects SSRF via the Next.js image optimization endpoint"
)

var (
	ModuleDesc = `**What it means:** The Next.js image optimization endpoint (/_next/image) accepts a url parameter and fetches that URL server-side, and this target does so without restricting it to safe destinations. That is a Server-Side Request Forgery (SSRF) flaw: the application can be coerced into making requests to hosts the attacker chooses, including internal-only systems the attacker cannot reach directly.

**How it's exploited:** An attacker requests /_next/image with a url pointing at an internal address, such as cloud metadata services (AWS 169.254.169.254, GCP metadata.google.internal, Azure) or localhost, and the server fetches it and returns the contents. The scanner confirms this either out-of-band via an OAST callback or in-band by matching metadata or localhost response markers in the optimizer output. Successful access to cloud metadata can leak temporary credentials and instance secrets, and internal addressing can be used to reach and probe otherwise-unexposed internal services.

**Fix:** Restrict the image optimizer to an allowlist of trusted external image domains (the images.domains / remotePatterns config) and block requests to internal, private, and link-local addresses.`

	ModuleConfirmation = "Confirmed when the image optimizer fetches an attacker-controlled or internal URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "ssrf", "moderate"}
)
