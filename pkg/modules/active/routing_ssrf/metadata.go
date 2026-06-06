package routing_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "routing-ssrf"
	ModuleName  = "Routing-Based SSRF (Request-Line)"
	ModuleShort = "Detects reverse-proxy routing SSRF via absolute-URI and userinfo/protocol-relative request-line targets"
)

var (
	ModuleDesc = `## Description
Detects routing-based Server-Side Request Forgery against reverse proxies, load
balancers, and TLS terminators, using the request-line techniques from
PortSwigger's "Cracking the lens: targeting HTTPS' hidden attack surface".

A proxy chooses a backend per request. Many proxies validate (or allowlist) the
Host header but forget that the **request line** can independently name a host —
in absolute form (` + "`GET http://internal/ HTTP/1.1`" + `), via a userinfo trick
(` + "`GET @attacker/ HTTP/1.1`" + `), or protocol-relative (` + "`GET //attacker/ HTTP/1.1`" + `).
When the proxy routes on the request-line host but trusts the Host header, an
attacker connected to the victim can make the proxy reach an arbitrary backend.

The module connects to the real victim host but writes an attacker-chosen literal
request target on the wire (via the requester's RawRequestTarget primitive), while
sending a valid Host header. It uses two oracles:

- **Out-of-band (OAST):** the request target names an OAST collaborator host. A
  callback from the proxy's network confirms the proxy fetched it — the strongest
  possible signal (no false positives). Findings arrive asynchronously.
- **In-band (internal/metadata):** the request target names an internal address or
  a cloud metadata endpoint (AWS/GCP/Azure/DigitalOcean/Alibaba). A finding is
  raised only when a self-evidencing marker (ami-id, droplet_id, …) appears,
  reproduces, is ABSENT from a fresh baseline of the original request, and does NOT
  appear for a benign decoy target — so the marker must come from the reached
  endpoint, not a catch-all.

## Notes
- Once per host (heavy). OAST oracle requires an interactsh server.
- The request line is sent un-normalized; the connection still goes to the victim.
- OWASP Top 10 2021: A10 (SSRF)

## References
- https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/`

	ModuleConfirmation = "OAST oracle: confirmed by an out-of-band callback from the proxy. In-band oracle: confirmed when an internal/metadata marker appears, reproduces, is absent from the original-request baseline, and absent for a decoy target."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "proxy", "routing", "request-line", "oast", "heavy"}
)
