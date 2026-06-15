package subresource_integrity_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "subresource-integrity-detect"
	ModuleName  = "Subresource Integrity Detect"
	ModuleShort = "Detects external resources loaded without subresource integrity"
)

var (
	ModuleDesc = `**What it means:** This page loads JavaScript or CSS from an external origin (CDN or third party) without a Subresource Integrity (SRI) attribute. The scanner flags external script and stylesheet tags with no integrity hash.

**How it's exploited:** If the CDN is breached, hijacked, or serves a malicious update, the attacker-controlled script runs in this site's origin - stealing sessions, modifying content, and harvesting credentials. SRI would make the browser refuse a tampered file.

**Fix:** Add an integrity attribute with a SHA-256/384/512 hash (and crossorigin) to every external script and stylesheet, or self-host them.`

	ModuleConfirmation = "Confirmed when external script or stylesheet is loaded without an integrity attribute"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "javascript", "light"}
)
