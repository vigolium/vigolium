package proxy_header_trust

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "proxy-header-trust"
	ModuleName  = "Proxy Header Trust"
	ModuleShort = "Cross-framework detection of proxy header trust issues via X-Forwarded-* header manipulation"
)

var (
	ModuleDesc = `**What it means:** Credential-preserving controls show that a client-supplied X-Forwarded-* value reproducibly changes URL generation, protocol behavior, or IP-gated access. Generic reflection and status-only changes remain candidates.

**How it's exploited:** Attackers may poison security-sensitive URLs, confuse HTTPS handling, or impersonate a trusted source IP. An IP bypass becomes a finding only when an unrelated-IP control stays denied and stable, distinct content is returned.

**Fix:** Have the edge proxy strip and re-set X-Forwarded-* and honor them only from known proxy IPs.`

	ModuleConfirmation = "Candidates require replay and value-specific controls; a finding requires reproducible IP-denial bypass plus stable content distinct from denial responses"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "moderate"}
)
