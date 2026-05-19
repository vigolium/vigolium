package metaframework_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "metaframework-probe"
	ModuleName  = "Metaframework Probe"
	ModuleShort = "Detects exposed Remix, Astro, and SvelteKit internal files and endpoints"
)

var (
	ModuleDesc = `## Description
Probes for framework-specific internal files and debug endpoints exposed by modern
JavaScript meta-frameworks including Remix, Astro, and SvelteKit. These frameworks
may inadvertently expose manifest files, build directories, version information,
and development endpoints in production deployments.

## Notes
- Runs once per host with internal deduplication
- Tests 8 framework-specific paths across Remix, Astro, and SvelteKit
- Each probe has tailored response matching to reduce false positives

## References
- https://remix.run/docs/en/main
- https://docs.astro.build/en/getting-started/
- https://kit.svelte.dev/docs/introduction`

	ModuleConfirmation = "Confirmed when the server responds with framework-specific content at known internal paths, indicating exposed build artifacts or debug endpoints"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "misconfiguration", "light"}
)
