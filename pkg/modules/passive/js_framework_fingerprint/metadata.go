package js_framework_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "js-framework-fingerprint"
	ModuleName  = "JS Framework Fingerprint"
	ModuleShort = "Identifies JavaScript frameworks (Next.js, Nuxt, Angular, React, Remix, SvelteKit, Gatsby)"
)

var (
	ModuleDesc = `## Description
Passively identifies the JavaScript framework powering a web application by analyzing
HTML response bodies and HTTP headers for framework-specific markers. Stores results
in a shared per-host cache used by other framework-specific modules.

## Notes
- Passive only — does not send any HTTP requests
- Detects: Next.js (Pages/App Router), Nuxt.js, Angular, React CRA, Remix, SvelteKit, Gatsby
- Extracts Next.js buildId for use by active Next.js modules
- Deduplicates by host to avoid redundant processing
- Requires strong signals (script tags or headers) to avoid false positives

## References
- https://nextjs.org/docs
- https://nuxt.com/docs
- https://angular.dev`

	ModuleConfirmation = "Confirmed when framework-specific markers (script tags, headers, or asset URL patterns) are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"javascript", "fingerprint", "nextjs", "angular", "react", "light"}
)
