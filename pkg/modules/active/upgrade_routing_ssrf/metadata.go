package upgrade_routing_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "upgrade-routing-ssrf"
	ModuleName  = "WebSocket-Upgrade SSRF Filter Bypass"
	ModuleShort = "Detects internal/metadata SSRF reachable only when a Connection: Upgrade / Upgrade: websocket handshake bypasses a proxy URL filter"
)

var (
	ModuleDesc = `## Description
Detects routing/SSRF filter bypasses where adding a WebSocket-style upgrade
handshake (` + "`Connection: Upgrade`" + ` + ` + "`Upgrade: websocket`" + ` + ` + "`Sec-WebSocket-*`" + `)
causes a reverse proxy to forward a request to an internal backend it would
otherwise refuse — e.g. reaching the cloud metadata endpoint:

` + "```" + `
GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: localhost
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
` + "```" + `

This is a sibling of routing-ssrf, distinguished by its confirmation: a finding is
raised ONLY when the internal marker appears WITH the upgrade headers but is ABSENT
when the very same request is sent WITHOUT them. That differential proves the
upgrade handshake itself is the bypass — and avoids double-reporting a plain
request-line routing SSRF (which routing-ssrf already covers, with the marker
present in both cases).

## Notes
- Not part of the original "Cracking the lens" research; it targets the separate
  Upgrade/H2C smuggling class. Detection-only; once per host (heavy).
- Confirmation: marker present with-upgrade, absent without-upgrade, reproduces,
  and the response is not a WAF/block page. Drop-on-fail.
- OWASP Top 10 2021: A10 (SSRF)

## References
- https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/`

	ModuleConfirmation = "Confirmed when an internal/metadata marker appears only with the WebSocket upgrade headers present (absent without them), reproduces, and the response is not a block page."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "proxy", "websocket", "upgrade", "request-line", "heavy"}
)
