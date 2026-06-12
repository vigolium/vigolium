package nextjs_version_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-version-audit"
	ModuleName  = "Next.js Version Audit"
	ModuleShort = "Fingerprints Next.js version and maps to known CVE advisories"
)

var (
	ModuleDesc = `**What it means:** The application runs a Next.js version that is exposed in its client-side JavaScript bundles, and that version falls inside the affected range of one or more published security advisories. The reported severity reflects the most serious matched CVE, which may include critical issues such as the middleware authorization bypass (CVE-2025-29927), SSRF via Server Actions (CVE-2024-34351), cache-poisoning denial of service (CVE-2024-46982), and parallel-route auth bypass (CVE-2024-51479).
**How it's exploited:** An attacker reads the publicly served bundle to confirm the exact framework version, then launches the matching public exploit for that CVE; depending on which advisory applies, this can mean bypassing middleware authentication and reaching protected routes, forcing the server to make attacker-controlled outbound requests, or knocking the application offline.
**Fix:** Upgrade Next.js to a release at or above the fixed version listed for the matched advisory (latest patch in your major line).`

	ModuleConfirmation = "Confirmed when Next.js version is extracted and matches a known vulnerable version range"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "fingerprint", "light"}
)
