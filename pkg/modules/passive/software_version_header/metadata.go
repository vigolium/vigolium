package software_version_header

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "software-version-header"
	ModuleName  = "Software Version Header"
	ModuleShort = "Detects HTTP headers that disclose specific software version strings"
)

var (
	ModuleDesc = `**What it means:** The server returns HTTP response headers that disclose the exact version of its underlying software. This module passively flags version-disclosing headers (Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, X-Generator, X-Drupal-Cache, X-Varnish, X-Runtime, X-OWA-Version, X-SharePointHealthScore) only when they carry an actual version number, not just a product name. This is information disclosure that needlessly aids reconnaissance.

**How it's exploited:** Knowing a precise version (for example Apache 2.4.41 or PHP 8.1.2) lets an attacker look up published CVEs and exploits that affect exactly that build, then target the host directly instead of probing blindly. It also speeds up attack-surface mapping and fingerprinting of the technology stack.

**Fix:** Suppress or generalize these headers so they no longer expose version numbers (for example ServerTokens Prod, expose_php Off, and strip framework version headers at the application or proxy layer).`

	ModuleConfirmation = "Confirmed when HTTP response headers contain version-disclosing values with identifiable version numbers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"fingerprint", "info-disclosure", "light"}
)
