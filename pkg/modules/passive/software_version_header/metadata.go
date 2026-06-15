package software_version_header

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "software-version-header"
	ModuleName  = "Software Version Header"
	ModuleShort = "Detects HTTP headers that disclose specific software version strings"
)

var (
	ModuleDesc = `**What it means:** The server returns HTTP headers disclosing its exact software version. This passively flags version-revealing headers (Server, X-Powered-By, X-AspNet-Version, X-Runtime, X-OWA-Version) only when they carry an actual version number, not just a product name. Informational disclosure that aids reconnaissance.

**How it's exploited:** Knowing a precise version (for example Apache 2.4.41 or PHP 8.1.2) lets an attacker look up CVEs affecting exactly that build and target the host directly instead of probing blindly.

**Fix:** Suppress or generalize these headers (for example ServerTokens Prod, expose_php Off) and strip framework version headers at the proxy layer.`

	ModuleConfirmation = "Confirmed when HTTP response headers contain version-disclosing values with identifiable version numbers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"fingerprint", "info-disclosure", "light"}
)
