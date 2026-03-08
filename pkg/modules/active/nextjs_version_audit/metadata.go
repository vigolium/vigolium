package nextjs_version_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-version-audit"
	ModuleName  = "Next.js Version Audit"
	ModuleShort = "Fingerprints Next.js version and maps to known CVE advisories"
)

var (
	ModuleDesc = `## Description
Extracts the Next.js version from client-side JavaScript bundles and maps it to
known security advisories. Checks for critical vulnerabilities including middleware
auth bypass (CVE-2025-29927), SSRF via Server Actions (CVE-2024-34351), cache
poisoning (CVE-2024-46982), and Server Actions DoS (CVE-2024-39693).

## Notes
- Active per-host scanner - sends requests to /_next/static/ paths
- Extracts version from JS bundle patterns (e.g., "Next.js <version>")
- Falls back to __NEXT_DATA__ build metadata analysis
- Maps extracted version against a local CVE advisory database
- Deduplicates by host

## References
- https://github.com/vercel/next.js/security/advisories
- https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=next.js`

	ModuleConfirmation = "Confirmed when Next.js version is extracted and matches a known vulnerable version range"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"nextjs", "javascript", "fingerprint", "light"}
)
