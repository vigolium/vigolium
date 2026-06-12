package cloud_origin_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-origin-bypass"
	ModuleName  = "Cloud Origin Bypass"
	ModuleShort = "Detects direct access to cloud storage origins bypassing CDN security controls"
)

var (
	ModuleDesc = `**What it means:** The site is served through a CDN (CloudFront, Fastly, Akamai, Cloudflare, etc.), but its underlying cloud storage origin (S3, Google Cloud Storage, or Azure Blob) is leaked in the page body and is directly reachable. The exposed origin returns content successfully while missing security headers that the CDN adds (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security), so requests sent straight to the origin skip those CDN-layer protections.

**How it's exploited:** An attacker who connects to the origin bucket directly bypasses the WAF, rate limiting, and security headers enforced at the edge, regaining attack surface such as clickjacking, MIME sniffing, or HSTS downgrade that the CDN was meant to close, and can probe the bucket for misconfigured access or listable objects without the edge ever seeing the traffic.

**Fix:** Restrict origin access to the CDN only (S3 Origin Access Control / bucket policy, signed origin requests, or IP allowlisting) so the storage backend cannot be reached directly, and apply the same security headers at the origin.`

	ModuleConfirmation = "Confirmed when cloud storage origin is directly reachable with fewer security headers than the CDN-fronted endpoint"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "auth-bypass", "moderate"}
)
