package js_framework_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "js-framework-fingerprint"
	ModuleName  = "JS Framework Fingerprint"
	ModuleShort = "Identifies JavaScript frameworks (Next.js, Nuxt, Angular, React, Remix, SvelteKit, Gatsby)"
)

var (
	ModuleDesc = `**What it means:** The application reveals which JavaScript framework powers its front end (Next.js with Pages or App Router, Nuxt.js, Angular, React CRA, Remix, SvelteKit, or Gatsby), detected passively from HTML body markers such as __NEXT_DATA__, __NUXT__, ng-version, and asset URLs, plus headers like X-Powered-By. For Next.js it also surfaces the build identifier. This is informational technology disclosure, not a vulnerability on its own, but it narrows the attacker's search space.

**How it's exploited:** Knowing the exact framework lets an attacker focus reconnaissance and select framework-specific exploits and misconfigurations (for example Next.js data-fetching and middleware bypass classes, Nuxt SSR issues, or Angular template flaws) rather than probing blindly. The disclosed Next.js buildId and router type can be reused to reach internal data and asset endpoints and to fingerprint the deployed version for targeting.

**Fix:** Treat this as low-risk informational disclosure; you cannot fully hide a client-side framework, so instead remove unnecessary version and X-Powered-By headers, keep the framework patched, and ensure security does not rely on hiding the stack.`

	ModuleConfirmation = "Confirmed when framework-specific markers (script tags, headers, or asset URL patterns) are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "fingerprint", "nextjs", "angular", "react", "light"}
)
