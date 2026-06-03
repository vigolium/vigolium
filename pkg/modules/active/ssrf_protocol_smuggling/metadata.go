package ssrf_protocol_smuggling

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-protocol-smuggling"
	ModuleName  = "SSRF Protocol Smuggling (CRLF in URL)"
	ModuleShort = "Detects SSRF sinks that fetch CRLF-laden URLs enabling cross-protocol smuggling via OAST"
)

var (
	ModuleDesc = `## Description
Detects Server-Side Request Forgery sinks that accept a URL containing embedded CR-LF sequences,
which Orange Tsai's "A New Era of SSRF" showed can smuggle a second protocol (Redis, SMTP,
Memcached, gopher) over the fetcher's outbound connection. The module injects URLs whose host is
an OAST callback and whose path carries CR-LF + protocol commands; an OAST hit proves the server
fetched the CRLF-laden URL.

## Notes
- Sibling of ssrf-blind: that module sends plain OAST URLs; this one sends CRLF/cross-protocol
  smuggling payloads (Redis SLAVEOF, SMTP HELO, Memcached stats, gopher) and non-HTTP schemes,
  which some SSRF sinks require and which prove a smuggling-capable sink.
- DETECTABILITY LIMITATION: stock interactsh observes DNS and HTTP callbacks, not raw TCP/SMTP.
  An OAST hit therefore confirms the server fetched the CRLF URL (and reached the attacker host),
  but full confirmation that the smuggled protocol commands were honored requires a raw-capture
  OAST listener. Findings are reported at High; treat a confirmed smuggle (raw capture) as Critical.
- Requires an interactsh server; a no-op when OAST is disabled.
- Targets parameters whose name or value suggests URL input.
- Findings arrive asynchronously via the OAST polling callback; the smuggling variant rides in the
  callback's injection-type for attribution.
- OWASP Top 10 2021: A10 (SSRF).

## References
- https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/`

	ModuleConfirmation = "Confirmed when the target makes an outbound request (OAST callback) to a URL carrying embedded CR-LF and cross-protocol commands; smuggling of the embedded protocol requires raw-capture OAST to fully verify"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "heavy"}
)
