package nextjs_version_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-version-audit"
	ModuleName  = "Next.js Version Audit"
	ModuleShort = "Fingerprints Next.js version and maps to known CVE advisories"
)

var (
	ModuleDesc = `**What it means:** The Next.js version exposed in this site's client-side JavaScript bundles falls inside the affected range of published security advisories. Reported severity reflects the most serious matched CVE, which may include middleware authorization bypass (CVE-2025-29927), SSRF via Server Actions (CVE-2024-34351), cache-poisoning DoS (CVE-2024-46982), or parallel-route auth bypass (CVE-2024-51479).

**How it's exploited:** An attacker reads the served bundle to confirm the version, then runs the matching public exploit - bypassing middleware authentication, forcing outbound requests, or taking the app offline.

**Fix:** Upgrade Next.js to at or above the fixed version for the matched advisory.`

	ModuleConfirmation = "Confirmed when Next.js version is extracted and matches a known vulnerable version range"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "fingerprint", "light"}
)
