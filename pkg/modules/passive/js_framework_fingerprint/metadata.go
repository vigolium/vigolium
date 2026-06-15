package js_framework_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "js-framework-fingerprint"
	ModuleName  = "JS Framework Fingerprint"
	ModuleShort = "Identifies JavaScript frameworks (Next.js, Nuxt, Angular, React, Remix, SvelteKit, Gatsby)"
)

var (
	ModuleDesc = `**What it means:** The app reveals its front-end JavaScript framework (Next.js, Nuxt.js, Angular, React CRA, Remix, SvelteKit, or Gatsby), detected from HTML markers like __NEXT_DATA__, __NUXT__, ng-version, asset URLs, and X-Powered-By. For Next.js it surfaces the build identifier. Informational disclosure, not a vulnerability.

**How it's exploited:** An attacker selects framework-specific exploits (Next.js middleware bypass, Nuxt SSR issues, Angular template flaws) instead of probing blindly. The Next.js buildId and router type help reach internal data and asset endpoints.

**Fix:** Remove unnecessary version and X-Powered-By headers, keep the framework patched, and never rely on hiding the stack for security.`

	ModuleConfirmation = "Confirmed when framework-specific markers (script tags, headers, or asset URL patterns) are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "fingerprint", "nextjs", "angular", "react", "light"}
)
