package build_misconfig_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "build-misconfig-detect"
	ModuleName  = "Build Misconfiguration Detect"
	ModuleShort = "Detects build and deployment misconfigurations in framework config files"
)

var (
	ModuleDesc = `**What it means:** This passive check found a frontend build or deployment configuration (in an exposed config file such as next.config, vite.config, webpack.config, or package.json, or in a JS/TS/JSON bundle confirmed to embed build-config settings) that is left in an insecure state for production. Detected issues include production source maps enabled (Next.js productionBrowserSourceMaps, Vite/webpack sourcemap, webpack devtool source-map), a development-mode start script shipped in production package.json, Next.js dangerouslyAllowSVG enabled, and an overly broad image remotePatterns wildcard hostname. These settings leak source code, expose dev tooling, or widen attack surface.
**How it's exploited:** Source maps let an attacker reconstruct readable source and find secrets or logic flaws; dev-mode servers expose verbose errors and debug endpoints; allowing SVG through the image optimizer enables stored XSS; a wildcard image hostname lets the optimizer be pointed at arbitrary hosts for SSRF.
**Fix:** Disable source maps and dev settings in production builds, restrict image remotePatterns to trusted hostnames, and keep dangerouslyAllowSVG off.`

	ModuleConfirmation = "Confirmed when response body contains build or deployment configuration patterns that indicate misconfigurations in production"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "info-disclosure", "javascript", "light"}
)
