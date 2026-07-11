package nextjs_version_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-version-audit"
	ModuleName  = "Next.js Version Audit"
	ModuleShort = "Fingerprints Next.js version and maps to known CVE advisories"
)

var (
	ModuleDesc = `**What it means:** A Next.js-qualified version marker exposed by the site falls inside a branch-specific affected interval from a reviewed advisory. Generic application "version" fields are ignored. Advisories with deployment or feature prerequisites are candidates until those prerequisites are confirmed.

**How it's exploited:** An attacker reads the served bundle to confirm the version, then runs the matching public exploit - bypassing middleware authentication, forcing outbound requests, or taking the app offline.

**Fix:** Upgrade Next.js to at or above the fixed version for the matched advisory.`

	ModuleConfirmation = "Version match requires an explicitly Next.js-qualified marker and a reviewed branch-specific interval; prerequisite-dependent advisories remain candidates"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "fingerprint", "light"}
)
