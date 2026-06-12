package upgrade_routing_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "upgrade-routing-ssrf"
	ModuleName  = "WebSocket-Upgrade SSRF Filter Bypass"
	ModuleShort = "Detects internal/metadata SSRF reachable only when a Connection: Upgrade / Upgrade: websocket handshake bypasses a proxy URL filter"
)

var (
	ModuleDesc = `**What it means:** A reverse proxy or gateway in front of the application can be tricked into forwarding a request to an internal-only backend when the request carries a WebSocket-style upgrade handshake (Connection: Upgrade plus Upgrade: websocket and Sec-WebSocket-* headers). This is a Server-Side Request Forgery (SSRF) filter bypass: the upgrade handshake makes the proxy route traffic it would normally refuse, reaching addresses the attacker should never be able to touch.

**How it's exploited:** An attacker sends a request with an absolute-form request line pointing at an internal target (for example the cloud metadata service at 169.254.169.254 or other private hosts) together with the upgrade headers. The same request without those headers is rejected, proving the handshake is the bypass. This lets the attacker read internal services or steal cloud instance credentials and metadata, often leading to full account or infrastructure compromise.

**Fix:** Reject or strip Upgrade/Connection handshake headers on non-WebSocket routes, validate the request-line target after upgrade parsing, and block proxy egress to internal and link-local address ranges.`

	ModuleConfirmation = "Confirmed when an internal/metadata marker appears only with the WebSocket upgrade headers present (absent without them), reproduces, and the response is not a block page."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "proxy", "websocket", "upgrade", "request-line", "heavy"}
)
