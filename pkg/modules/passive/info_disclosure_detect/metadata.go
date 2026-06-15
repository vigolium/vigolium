package info_disclosure_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "info-disclosure-detect"
	ModuleName  = "Info Disclosure Detect"
	ModuleShort = "Detects information disclosure patterns in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The response leaks internal technical details - software versions in Server / X-Powered-By headers, private IP addresses, stack traces, debug banners, or directory listings. None is a vulnerability alone, but each gives an attacker reconnaissance.

**How it's exploited:** An attacker uses disclosed version strings to look up version-specific CVEs, maps the internal network from leaked IPs, and reads stack traces or debug pages to learn file paths and other endpoints - sharpening follow-up attacks.

**Fix:** Suppress version banners and framework headers, disable debug mode and directory indexing in production, and return generic errors instead of stack traces.`

	ModuleConfirmation = "Confirmed when response contains identifiable server versions, internal IPs, stack traces, or debug information"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
