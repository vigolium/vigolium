package nextjs_config_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-config-audit"
	ModuleName  = "Next.js Config Audit"
	ModuleShort = "Detects insecure Next.js configuration patterns"
)

var (
	ModuleDesc = `**What it means:** A Next.js config or bundled JS/JSON contains an insecure setting. The module reports the matched pattern: dangerouslyAllowSVG:true, a wildcard image remotePatterns hostname, an http image protocol, productionBrowserSourceMaps:true, an /api/internal route exposed via rewrites, or images lacking security headers.

**How it's exploited:** Impact varies: a malicious SVG lands stored XSS, the wildcard image proxy reaches internal hosts (SSRF), leaked source maps reveal logic and secrets, or internal API routes become reachable.

**Fix:** Restrict remotePatterns to trusted hosts, disable dangerouslyAllowSVG and production source maps, use HTTPS, and add security headers.`

	ModuleConfirmation = "Confirmed when insecure configuration patterns are found in Next.js config files"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "misconfiguration", "light"}
)
