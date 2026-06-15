package mixed_content_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mixed-content-detect"
	ModuleName  = "Mixed Content Detect"
	ModuleShort = "Detects mixed HTTP/HTTPS content in responses"
)

var (
	ModuleDesc = `**What it means:** This HTTPS page loads sub-resources over plain HTTP via src, href, or action attributes, breaking encryption since those resources travel unprotected.

**How it's exploited:** An attacker on the network path (shared Wi-Fi, malicious proxy, compromised upstream) intercepts or tampers with HTTP-loaded resources in transit. A modified script or stylesheet runs code in the page's origin, while image or form-action references can leak data or redirect submissions.

**Fix:** Serve every sub-resource and form action over HTTPS, and add a Content-Security-Policy upgrade-insecure-requests directive.`

	ModuleConfirmation = "Confirmed when HTTPS page contains references to resources loaded over insecure HTTP"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"misconfiguration", "cryptography", "light"}
)
