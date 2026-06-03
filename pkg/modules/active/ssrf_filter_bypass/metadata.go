package ssrf_filter_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-filter-bypass"
	ModuleName  = "SSRF Filter Bypass (URL Parser Confusion)"
	ModuleShort = "Detects SSRF allowlist bypass via URL-parser authority confusion using OAST callbacks"
)

var (
	ModuleDesc = `## Description
Detects Server-Side Request Forgery where an application validates/allowlists the host of a
user-supplied URL but the component that actually fetches it disagrees about which host the URL
names. By placing a host the application is expected to trust (the target's own domain) and an
OAST callback host into a single URL using parser divergences — userinfo (` + "`@`" + `),
multiple ` + "`@`" + `, fragment (` + "`#`" + `), whitespace, and backslash — a value that
passes the allowlist still causes the server to connect to the attacker-controlled host. An
out-of-band callback proves the fetcher resolved to the attacker host despite the trusted-looking
parsed host.

Based on Orange Tsai's "A New Era of SSRF — Exploiting URL Parser in Trending Programming
Languages" (Black Hat USA 2017).

## Notes
- Sibling of ssrf-detection (overt internal URLs, in-band markers) and ssrf-blind (plain OAST
  URLs). This module adds the parser-confusion ladder with a trusted decoy host, targeting
  allowlist/validator bypass specifically.
- Requires an interactsh server (configured via oast settings); a no-op when OAST is disabled.
- Targets parameters whose name or value suggests URL input.
- Findings arrive asynchronously via the OAST polling callback; the confusion variant is recorded
  in the callback's injection-type for attribution.
- Self-confirming: an OAST callback IS the confirmation, so no in-band re-confirmation is needed.
- OWASP Top 10 2021: A10 (SSRF).

## References
- https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/`

	ModuleConfirmation = "Confirmed when the target makes an outbound DNS/HTTP request to the OAST host embedded in a parser-confusion URL whose parsed host is a trusted decoy"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "heavy"}
)
