package ssrf_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-detection"
	ModuleName  = "SSRF Detection"
	ModuleShort = "Detects server-side request forgery via out-of-band and in-band techniques"
)

var (
	ModuleDesc = `**What it means:** A Server-Side Request Forgery (SSRF) vulnerability lets an attacker make the server itself send HTTP requests to addresses of the attacker's choosing. The scanner injected internal targets into a URL-like parameter and the server fetched them, returning content it should never expose, such as localhost pages, cloud metadata, or internal services.

**How it's exploited:** An attacker supplies a URL pointing at an internal resource (127.0.0.1 in various encodings, file:///etc/passwd, or cloud metadata endpoints like 169.254.169.254 on AWS/Azure/DigitalOcean and metadata.google.internal on GCP). The server fetches it and relays the response, exposing the internal network, files, or Redis/MongoDB services, and on cloud hosts the metadata service can leak temporary IAM credentials that enable full account takeover.

**Fix:** Validate user-supplied URLs against a strict allowlist of hosts and schemes, block requests to loopback, link-local, and private address ranges (including encoded forms), disable unneeded URL schemes, and require IMDSv2 / session tokens on cloud metadata endpoints.`

	ModuleConfirmation = "Confirmed when injected internal URLs or metadata endpoints cause different response content or timing compared to baseline"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "moderate"}
)
