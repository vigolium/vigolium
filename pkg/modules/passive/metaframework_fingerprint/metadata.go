package metaframework_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "metaframework-fingerprint"
	ModuleName  = "Meta-Framework Fingerprint"
	ModuleShort = "Identifies Remix, Astro, SvelteKit, Solid, and Qwik meta-frameworks"
)

var (
	ModuleDesc = `**What it means:** The app is built on a JavaScript meta-framework (Remix, Astro, SvelteKit, SolidStart, or Qwik), identified from hydration markers, asset URL patterns, or response headers. Informational recon, not a vulnerability.

**How it's exploited:** An attacker maps the likely server-side runtime (Node.js), route conventions, and data-loading endpoints, then targets framework-specific issues such as SSR injection, hydration mismatches, or exposed loader/action routes.

**Fix:** Strip identifying headers and markers only if concealment is desired, and keep the framework and its dependencies patched to current versions.`

	ModuleConfirmation = "Confirmed when framework-specific markers (hydration scripts, asset URL patterns, or headers) are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "fingerprint", "light"}
)
