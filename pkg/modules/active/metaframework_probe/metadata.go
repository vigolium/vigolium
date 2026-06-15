package metaframework_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "metaframework-probe"
	ModuleName  = "Metaframework Probe"
	ModuleShort = "Detects exposed Remix, Astro, and SvelteKit internal files and endpoints"
)

var (
	ModuleDesc = `**What it means:** A JavaScript meta-framework (Remix, Astro, or SvelteKit) serves an internal build artifact or dev endpoint in production - the Remix route manifest or dev/HMR endpoint, Astro build and dev-toolbar directories, or SvelteKit version.json and data routes. An information-disclosure misconfiguration.

**How it's exploited:** An attacker reads these artifacts to map the route table, bundles, and directory structure, and to fingerprint the framework and build version, helping target version-specific vulnerabilities and find hidden routes.

**Fix:** Build for production with dev endpoints disabled and block public access to internal build and dot directories (.astro, .svelte-kit, _astro) and manifest/data routes.`

	ModuleConfirmation = "Confirmed when an internal path returns framework-specific structured content (real JSON keys or a directory autoindex) that differs from the host's catch-all/SPA shell, indicating exposed build artifacts or debug endpoints"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "misconfiguration", "light"}
)
