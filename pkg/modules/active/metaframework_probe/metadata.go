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
- Probes a random nonexistent path first and drops any match that merely
  returns the host's single-page-app / wildcard catch-all shell
- Each probe demands artifact-specific content: JSON endpoints require the real
  JSON keys and a non-HTML Content-Type; directory probes require an actual
  "Index of /" autoindex listing — never a bare generic substring

## References
- https://remix.run/docs/en/main
- https://docs.astro.build/en/getting-started/
- https://kit.svelte.dev/docs/introduction`

	ModuleConfirmation = "Confirmed when an internal path returns framework-specific structured content (real JSON keys or a directory autoindex) that differs from the host's catch-all/SPA shell, indicating exposed build artifacts or debug endpoints"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "misconfiguration", "light"}
)
