package http_request_smuggling

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "http-request-smuggling"
	ModuleName  = "HTTP Request Smuggling"
	ModuleShort = "Detects HTTP request smuggling via CL.TE and TE.CL desync"
)

var (
	ModuleDesc = `## Description
Detects HTTP request smuggling vulnerabilities by sending ambiguous requests with
conflicting Content-Length and Transfer-Encoding headers to identify desync behavior.

## Notes
- Tests CL.TE and TE.CL desync patterns
- Uses differential timing analysis to detect smuggling
- Runs once per host to avoid disruption
- Requires careful timeout configuration

## False-positive controls
A single slow response is never enough — timing is prone to jitter, general
latency, and CDN/WAF edge blocks. A timing anomaly is only reported when:
- the host's baseline response is not itself an edge/CDN/WAF block;
- the probe response is not an edge/CDN/WAF block (e.g. a Cloudflare 403
  "Edge IP Restricted" page is rejected at the edge, not desynced);
- the anomaly reproduces on a second send of the same probe; and
- a well-formed control POST of similar shape returns quickly (ruling out
  general host/path latency).

## References
- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/research/http-desync-attacks`

	ModuleConfirmation = "Confirmed when conflicting CL/TE headers cause a reproducible response timing anomaly that a well-formed control request does not, and the response is not an edge/CDN/WAF block"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"request-smuggling", "heavy"}
)
