package routing_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "routing-ssrf"
	ModuleName  = "Routing-Based SSRF (Request-Line)"
	ModuleShort = "Detects reverse-proxy routing SSRF via absolute-URI and userinfo/protocol-relative request-line targets"
)

var (
	ModuleDesc = `**What it means:** A reverse proxy or load balancer routes by the HTTP request line rather than the validated Host header, so an attacker can make it connect to a backend of their choosing - a routing-based SSRF that pivots into internal networks.

**How it's exploited:** The attacker names an arbitrary target in the request line (absolute, userinfo, or protocol-relative form) while keeping a valid Host header. The proxy fetches it, reaching internal services or cloud metadata to steal credentials. Confirmed by out-of-band callback.

**Fix:** Route strictly on the validated Host header and reject request lines naming an absolute target.`

	ModuleConfirmation = "OAST oracle: confirmed by an out-of-band callback from the proxy (Certain). In-band oracle (Tentative): reported only when a plain (non-HTML) metadata body carries several distinct self-evidencing tokens together, the cluster reproduces, is absent from the original-request baseline, and is absent for a benign decoy target."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "proxy", "routing", "request-line", "oast", "heavy"}
)
