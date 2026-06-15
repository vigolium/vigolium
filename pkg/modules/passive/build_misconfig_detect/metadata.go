package build_misconfig_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "build-misconfig-detect"
	ModuleName  = "Build Misconfiguration Detect"
	ModuleShort = "Detects build and deployment misconfigurations in framework config files"
)

var (
	ModuleDesc = `**What it means:** A frontend build config (next.config, vite.config, webpack.config, package.json) is left insecure for production. Detected issues: production source maps enabled, a dev-mode start script in production package.json, Next.js dangerouslyAllowSVG on, and an overly broad image remotePatterns wildcard hostname.

**How it's exploited:** Source maps let an attacker reconstruct source and find secrets; dev-mode servers expose verbose errors and debug endpoints; SVG through the image optimizer enables stored XSS; a wildcard image hostname enables SSRF.

**Fix:** Disable source maps and dev settings in production builds, restrict image remotePatterns to trusted hostnames, and keep dangerouslyAllowSVG off.`

	ModuleConfirmation = "Confirmed when response body contains build or deployment configuration patterns that indicate misconfigurations in production"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "info-disclosure", "javascript", "light"}
)
