package metaframework_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "metaframework-probe"
	ModuleName  = "Metaframework Probe"
	ModuleShort = "Detects exposed Remix, Astro, and SvelteKit internal files and endpoints"
)

var (
	ModuleDesc = `**What it means:** A modern JavaScript meta-framework (Remix, Astro, or SvelteKit) is serving an internal build artifact or development endpoint in production that should not be publicly reachable. Confirmed examples include the Remix route manifest, the Remix dev/HMR endpoint, Astro build and dev-toolbar directories, the SvelteKit version.json and build directory, and SvelteKit data endpoints. This is an information-disclosure and attack-surface misconfiguration, not a direct code-execution flaw.

**How it's exploited:** An attacker reads these artifacts to map the application's full route table, entry bundles, and internal directory structure, and to fingerprint the exact framework and build version. That intelligence helps target version-specific vulnerabilities, locate hidden or privileged routes, and expand reconnaissance for further attacks. Exposed dev/HMR or dev-toolbar endpoints can also indicate a development build accidentally shipped to production.

**Fix:** Build for production with development endpoints disabled and block public access to internal build and dot directories (.astro, .svelte-kit, _astro, manifest and data routes) at the web server or CDN.`

	ModuleConfirmation = "Confirmed when an internal path returns framework-specific structured content (real JSON keys or a directory autoindex) that differs from the host's catch-all/SPA shell, indicating exposed build artifacts or debug endpoints"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "misconfiguration", "light"}
)
