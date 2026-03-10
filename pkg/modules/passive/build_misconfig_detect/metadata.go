package build_misconfig_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "build-misconfig-detect"
	ModuleName  = "Build Misconfiguration Detect"
	ModuleShort = "Detects build and deployment misconfigurations in framework config files"
)

var (
	ModuleDesc = `## Description
Scans JavaScript, TypeScript, and JSON response bodies for build and deployment
misconfigurations in modern frontend frameworks. Detects production source maps
enabled (Next.js, Vite, webpack), development mode start scripts in production
package.json, dangerous SVG handling in Next.js image optimization, and overly
broad image remote patterns. These misconfigurations can leak source code,
expose development tooling, or enable SSRF attacks.

## Notes
- Passive only -- does not send any HTTP requests
- Scans JS/TS/JSON responses and config file URLs
- Detects: source maps in prod, dev mode in prod, SVG XSS risk, broad image remotePatterns
- Deduplicates by host

## References
- https://nextjs.org/docs/app/api-reference/next-config-js/productionBrowserSourceMaps
- https://vitejs.dev/config/build-options.html#build-sourcemap
- https://webpack.js.org/configuration/devtool/
- https://cwe.mitre.org/data/definitions/540.html
- https://cwe.mitre.org/data/definitions/489.html`

	ModuleConfirmation = "Confirmed when response body contains build or deployment configuration patterns that indicate misconfigurations in production"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"misconfiguration", "info-disclosure", "javascript", "light"}
)
