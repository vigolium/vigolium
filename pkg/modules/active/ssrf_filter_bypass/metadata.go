package ssrf_filter_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-filter-bypass"
	ModuleName  = "SSRF Filter Bypass (URL Parser Confusion)"
	ModuleShort = "Detects SSRF allowlist bypass via URL-parser authority confusion using OAST callbacks"
)

var (
	ModuleDesc = `**What it means:** The application accepts a URL in this parameter and fetches it server-side, but its host allowlist/validator can be tricked by URL-parser confusion. The validator and the HTTP client disagree about which host a crafted URL actually names, so a URL that looks trusted is fetched against an attacker-chosen host. This is a Server-Side Request Forgery (SSRF) allowlist bypass, confirmed here by an out-of-band callback to a scanner-controlled OAST host.

**How it's exploited:** An attacker crafts a single URL that embeds a trusted-looking decoy host (the target's own domain) plus a malicious host using parser divergences such as userinfo (an at-sign), multiple at-signs, a fragment, whitespace, or a backslash. The validator approves it while the fetcher connects to the malicious host, letting the attacker reach internal services, cloud metadata endpoints, or other hosts the allowlist was meant to protect.

**Fix:** Resolve and re-validate the final connection target after parsing with a hardened parser, allowlist only fully-resolved hosts/IPs, and reject userinfo, embedded credentials, and ambiguous authority syntax.`

	ModuleConfirmation = "Confirmed when the target makes an outbound DNS/HTTP request to the OAST host embedded in a parser-confusion URL whose parsed host is a trusted decoy"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "heavy"}
)
