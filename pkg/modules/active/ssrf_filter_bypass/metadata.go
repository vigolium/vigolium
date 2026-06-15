package ssrf_filter_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-filter-bypass"
	ModuleName  = "SSRF Filter Bypass (URL Parser Confusion)"
	ModuleShort = "Detects SSRF allowlist bypass via URL-parser authority confusion using OAST callbacks"
)

var (
	ModuleDesc = `**What it means:** The app fetches a URL from this parameter server-side, but URL-parser confusion lets a trusted-looking URL reach an attacker-chosen host. This SSRF allowlist bypass is confirmed by an OAST callback.

**How it's exploited:** An attacker crafts a URL embedding a trusted decoy plus a malicious host via parser divergences like userinfo at-signs, fragments, whitespace, or backslashes, so the validator approves it but the fetcher connects to the malicious one.

**Fix:** Re-validate the final connection target with a hardened parser, allowlist only fully-resolved hosts/IPs, and reject userinfo and ambiguous syntax.`

	ModuleConfirmation = "Confirmed when the target makes an outbound DNS/HTTP request to the OAST host embedded in a parser-confusion URL whose parsed host is a trusted decoy"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "heavy"}
)
