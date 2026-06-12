package routing_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "routing-ssrf"
	ModuleName  = "Routing-Based SSRF (Request-Line)"
	ModuleShort = "Detects reverse-proxy routing SSRF via absolute-URI and userinfo/protocol-relative request-line targets"
)

var (
	ModuleDesc = `**What it means:** A reverse proxy, load balancer, or TLS terminator in front of this site routes requests based on the HTTP request line rather than the validated Host header, so an attacker can make the proxy connect to a backend of their choosing. This is a routing-based Server-Side Request Forgery (SSRF) flaw that lets an external attacker pivot through the trusted proxy into internal networks.

**How it's exploited:** The attacker sends a request whose request line names an attacker-chosen target in absolute form (GET http://internal/), userinfo form (GET @attacker/), or protocol-relative form (GET //attacker/), while keeping a valid Host header. The proxy fetches that target, reaching internal services or cloud metadata endpoints (AWS/GCP/Azure/etc.) to steal credentials, instance data, or unexposed admin interfaces. The scanner confirms this via an out-of-band callback, or an internal marker that reproduces and is absent for a baseline and a decoy.

**Fix:** Configure the proxy to route strictly on the validated Host header and reject request lines that name an arbitrary external or absolute target.`

	ModuleConfirmation = "OAST oracle: confirmed by an out-of-band callback from the proxy. In-band oracle: confirmed when an internal/metadata marker appears, reproduces, is absent from the original-request baseline, and absent for a decoy target."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "proxy", "routing", "request-line", "oast", "heavy"}
)
