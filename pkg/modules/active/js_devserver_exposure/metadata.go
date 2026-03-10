package js_devserver_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "js-devserver-exposure"
	ModuleName  = "JS Dev Server Exposure"
	ModuleShort = "Detects exposed JavaScript development server endpoints (webpack HMR, Vite, Nuxt)"
)

var (
	ModuleDesc = `## Description
Probes for exposed JavaScript development server endpoints that should never be
accessible in production. Development servers expose hot module replacement (HMR)
endpoints, debug tools, and internal APIs that leak source code, enable code injection,
or reveal server internals.

## Notes
- Runs once per host
- Probes: webpack HMR, Vite ping, webpack dev server sockjs, Vue CLI open-in-editor, Nuxt HMR, Remix dev
- Validates via Content-Type and response body markers
- Fingerprints 404 to avoid false positives on custom error pages

## References
- https://webpack.js.org/configuration/dev-server/
- https://vitejs.dev/config/server-options`

	ModuleConfirmation = "Confirmed when a dev server endpoint responds with expected Content-Type or markers"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "nuxt", "misconfiguration", "info-disclosure", "light"}
)
