package metaframework_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "metaframework-fingerprint"
	ModuleName  = "Meta-Framework Fingerprint"
	ModuleShort = "Identifies Remix, Astro, SvelteKit, Solid, and Qwik meta-frameworks"
)

var (
	ModuleDesc = `**What it means:** The target application is built on a modern JavaScript meta-framework (Remix, Astro, SvelteKit, SolidStart, or Qwik), identified passively from hydration markers, asset URL patterns, or response headers in the served HTML. This is an informational fingerprint, not a vulnerability on its own, but it discloses a concrete technology stack that an attacker can use to narrow their approach.

**How it's exploited:** Knowing the exact framework lets an attacker map the likely server-side runtime (Node.js), route conventions, and data-loading endpoints, then target framework-specific and version-specific known issues such as SSR injection, hydration mismatches, or exposed loader/action routes. It speeds reconnaissance and selection of relevant exploits against the rest of the surface.

**Fix:** This is expected behavior; reduce fingerprinting only if framework concealment is desired by stripping identifying headers and markers, and ensure the framework and its dependencies are kept patched to current versions.`

	ModuleConfirmation = "Confirmed when framework-specific markers (hydration scripts, asset URL patterns, or headers) are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "fingerprint", "light"}
)
