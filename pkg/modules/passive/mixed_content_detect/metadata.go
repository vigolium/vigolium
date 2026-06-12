package mixed_content_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mixed-content-detect"
	ModuleName  = "Mixed Content Detect"
	ModuleShort = "Detects mixed HTTP/HTTPS content in responses"
)

var (
	ModuleDesc = `**What it means:** This HTTPS page loads one or more sub-resources over plain HTTP, referenced in src, href, or action attributes of its HTML. These insecure references break the page's encryption guarantee because the embedded resources travel unprotected even though the main document is served over TLS.

**How it's exploited:** An attacker on the network path (shared Wi-Fi, malicious proxy, compromised upstream) can intercept or tamper with the HTTP-loaded resources in transit. Modifying a script or stylesheet loaded this way lets them inject content or run code in the page's origin, while image or form-action references can leak data or redirect submissions to an attacker-controlled endpoint. Browsers typically block or downgrade active mixed content, but passive references still expose users to interception.

**Fix:** Serve every sub-resource and form action over HTTPS, replacing all http:// URLs with https:// (or protocol-relative/relative references), and add a Content-Security-Policy upgrade-insecure-requests directive to catch any that remain.`

	ModuleConfirmation = "Confirmed when HTTPS page contains references to resources loaded over insecure HTTP"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"misconfiguration", "cryptography", "light"}
)
