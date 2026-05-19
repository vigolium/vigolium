package metaframework_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "metaframework-fingerprint"
	ModuleName  = "Meta-Framework Fingerprint"
	ModuleShort = "Identifies Remix, Astro, SvelteKit, Solid, and Qwik meta-frameworks"
)

var (
	ModuleDesc = `## Description
Passively identifies newer JavaScript meta-frameworks by analyzing HTML response bodies
and HTTP headers for framework-specific markers. Complements the existing js-framework-fingerprint
module which covers Next.js, Nuxt, Angular, React, and Gatsby.

## Notes
- Passive only — does not send any HTTP requests
- Detects: Remix, Astro, SvelteKit, SolidStart, Qwik
- Uses strong signals (hydration markers, asset URL patterns, headers) to avoid false positives
- Deduplicates by host to fingerprint each host only once

## References
- https://remix.run/docs
- https://docs.astro.build
- https://svelte.dev/docs/kit
- https://start.solidjs.com
- https://qwik.dev`

	ModuleConfirmation = "Confirmed when framework-specific markers (hydration scripts, asset URL patterns, or headers) are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "fingerprint", "light"}
)
