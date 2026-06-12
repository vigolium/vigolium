package subresource_integrity_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subresource-integrity-detect"
	ModuleName  = "Subresource Integrity Detect"
	ModuleShort = "Detects external resources loaded without subresource integrity"
)

var (
	ModuleDesc = `**What it means:** This page loads JavaScript or CSS from an external origin (a CDN or third-party host) without a Subresource Integrity (SRI) integrity attribute. Without SRI, the browser executes whatever the third party serves, so it cannot detect if that file has been altered. The scanner flags external script and stylesheet tags in the HTML that have no integrity hash; it does not prove the third party is compromised.

**How it's exploited:** If the CDN or third-party host is breached, hijacked, or serves a malicious update, the attacker-controlled script runs in this site's origin, letting them steal sessions, read or modify page content, and harvest credentials affecting every visitor. SRI would cause the browser to refuse a file whose hash does not match, so its absence removes that safety net.

**Fix:** Add an integrity attribute with a SHA-256/384/512 hash (and crossorigin) to every external script and stylesheet tag, or self-host the resources.`

	ModuleConfirmation = "Confirmed when external script or stylesheet is loaded without an integrity attribute"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "javascript", "light"}
)
