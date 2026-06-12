package info_disclosure_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "info-disclosure-detect"
	ModuleName  = "Info Disclosure Detect"
	ModuleShort = "Detects information disclosure patterns in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The response leaks technical details about the application's internals - software versions in Server / X-Powered-By / X-AspNet(Mvc)-Version headers, private RFC 1918 IP addresses, framework stack traces, debug-mode banners (Werkzeug, Django, Laravel), or directory listings. None of these are vulnerabilities on their own, but each one hands an attacker reconnaissance that should not be exposed publicly.

**How it's exploited:** An attacker uses the disclosed version strings to look up and target version-specific known CVEs, maps the internal network from leaked private IPs, and reads stack traces or debug pages to learn file paths, framework internals, and other endpoints - sharpening follow-up attacks. The information itself does not grant access; it lowers the effort and increases the precision of later exploitation.

**Fix:** Suppress version banners and framework headers, disable debug mode and directory indexing in production, and configure error handling to return generic messages instead of stack traces.`

	ModuleConfirmation = "Confirmed when response contains identifiable server versions, internal IPs, stack traces, or debug information"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
