package nextjs_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-config-audit"
	ModuleName  = "Next.js Config Audit"
	ModuleShort = "Detects insecure Next.js configuration patterns"
)

var (
	ModuleDesc = `**What it means:** A response body (a Next.js config file or bundled JS/JSON served by the app) contains an insecure Next.js configuration setting. The module passively reports the specific pattern it matched: dangerouslyAllowSVG:true (allows SVG images that can carry XSS), a wildcard image remotePatterns hostname (lets the built-in image optimizer fetch any host, enabling SSRF), an http (non-HTTPS) image protocol (cleartext transport), productionBrowserSourceMaps:true (ships source maps that expose original source code), an /api/internal route exposed through rewrites or redirects, or an images config with no headers block defining security headers.
**How it's exploited:** Each pattern has a different impact: an attacker uploads a malicious SVG to land stored XSS, abuses the wildcard image proxy to reach internal hosts (SSRF), reads leaked source maps to map application logic and secrets, or reaches internal API routes directly. Severity per finding ranges from informational to high.
**Fix:** Restrict image remotePatterns to explicit trusted hosts, disable dangerouslyAllowSVG and production source maps, use HTTPS, avoid exposing internal API paths, and add a security-headers config.`

	ModuleConfirmation = "Confirmed when insecure configuration patterns are found in Next.js config files"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "misconfiguration", "light"}
)
