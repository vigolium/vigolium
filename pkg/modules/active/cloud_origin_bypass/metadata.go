package cloud_origin_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-origin-bypass"
	ModuleName  = "Cloud Origin Bypass"
	ModuleShort = "Detects direct access to cloud storage origins bypassing CDN security controls"
)

var (
	ModuleDesc = `**What it means:** The site is served via a CDN (CloudFront, Fastly, Akamai, Cloudflare), but its storage origin (S3, GCS, or Azure Blob) is leaked in the page body and directly reachable, returning content while missing headers the CDN adds (CSP, X-Frame-Options, HSTS).

**How it's exploited:** An attacker connecting to the origin directly bypasses the WAF, rate limiting, and edge headers, regaining attack surface like clickjacking, MIME sniffing, or HSTS downgrade.

**Fix:** Restrict origin access to the CDN only (S3 Origin Access Control, signed requests, or IP allowlisting), and apply the same headers at the origin.`

	ModuleConfirmation = "Confirmed when cloud storage origin is directly reachable with fewer security headers than the CDN-fronted endpoint"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "auth-bypass", "moderate"}
)
