package cloud_origin_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-origin-bypass"
	ModuleName  = "Cloud Origin Bypass"
	ModuleShort = "Detects direct access to cloud storage origins bypassing CDN security controls"
)

var (
	ModuleDesc = `## Description
Detects when cloud storage origins are directly reachable with weaker security controls
than the CDN/WAF layer. Identifies CDN presence from headers, extracts origin storage
URLs from response body, and compares security headers between CDN and origin.

## Notes
- Step 1: Detect CDN from CF-Ray, X-Cache, Via, X-Amz-Cf-Id, X-Served-By headers
- Step 2: Extract origin storage URLs from response body
- Step 3: Fetch origin directly and compare security headers
- Flags when origin is reachable with weaker controls (missing CSP, XFO, XCTO, HSTS)
- Runs once per host with deduplication

## References
- https://owasp.org/www-project-web-security-testing-guide/
- https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html`

	ModuleConfirmation = "Confirmed when cloud storage origin is directly reachable with fewer security headers than the CDN-fronted endpoint"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "auth-bypass", "moderate"}
)
