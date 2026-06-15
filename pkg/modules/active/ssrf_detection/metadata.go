package ssrf_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-detection"
	ModuleName  = "SSRF Detection"
	ModuleShort = "Detects server-side request forgery via out-of-band and in-band techniques"
)

var (
	ModuleDesc = `**What it means:** A Server-Side Request Forgery (SSRF) flaw lets an attacker make the server send HTTP requests to addresses of their choosing. Injecting internal targets into a URL-like parameter made the server fetch and return content it should never expose.

**How it's exploited:** An attacker supplies a URL pointing at an internal resource (encoded 127.0.0.1, file:///etc/passwd, or 169.254.169.254). The server relays the response, exposing the internal network, files, or Redis/MongoDB - and metadata can leak temporary IAM credentials.

**Fix:** Allowlist URL hosts and schemes, block loopback/link-local/private ranges (including encoded forms), and require IMDSv2 on cloud metadata.`

	ModuleConfirmation = "Confirmed when injected internal URLs or metadata endpoints cause different response content or timing compared to baseline"
	ModuleSeverity     = severity.High
	// In-band only: this module has no out-of-band oracle, so an in-response marker
	// can at most be Tentative. A Firm/Certain SSRF requires an OAST callback, which
	// the OAST-driven modules (ssrf-blind, routing-ssrf, …) supply.
	ModuleConfidence = severity.Tentative
	ModuleTags       = []string{"ssrf", "injection", "moderate"}
)
