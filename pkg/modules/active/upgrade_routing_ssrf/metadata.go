package upgrade_routing_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "upgrade-routing-ssrf"
	ModuleName  = "WebSocket-Upgrade SSRF Filter Bypass"
	ModuleShort = "Detects internal/metadata SSRF reachable only when a Connection: Upgrade / Upgrade: websocket handshake bypasses a proxy URL filter"
)

var (
	ModuleDesc = `**What it means:** A reverse proxy can be tricked into forwarding a request to an internal-only backend when it carries a WebSocket-style upgrade handshake (Connection: Upgrade plus Upgrade: websocket), routing SSRF traffic it would normally refuse.

**How it's exploited:** An attacker sends an absolute-form request line pointing at an internal target (e.g. the metadata service at 169.254.169.254) with the upgrade headers; the same request without them is rejected, proving the bypass. This lets them read internal services or steal cloud credentials.

**Fix:** Strip Upgrade/Connection headers on non-WebSocket routes and block proxy egress to internal and link-local ranges.`

	ModuleConfirmation = "Reported (Tentative) when a plain (non-HTML) metadata body carrying several distinct self-evidencing tokens appears only with the WebSocket upgrade headers present (absent without them), reproduces, and is not a block page."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"ssrf", "proxy", "websocket", "upgrade", "request-line", "heavy"}
)
