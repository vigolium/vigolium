package http_request_smuggling

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "http-request-smuggling"
	ModuleName  = "HTTP Request Smuggling"
	ModuleShort = "Detects HTTP request smuggling via CL.TE and TE.CL desync"
)

var (
	ModuleDesc = `**What it means:** A front-end proxy disagrees with the back-end about where one HTTP request ends and the next begins. Conflicting Content-Length and Transfer-Encoding framing (CL.TE, TE.CL, TE.TE variants) produced a reproducible timing anomaly consistent with desync. Timing-inferred and reported as suspect.

**How it's exploited:** An attacker prepends crafted bytes to a victim's pipelined request to poison the shared connection, hijacking other users' requests, stealing session cookies, or poisoning the response cache.

**Fix:** Make the front-end and back-end agree on framing: reject requests carrying both Content-Length and Transfer-Encoding, strip Transfer-Encoding at the edge, prefer HTTP/2.`

	ModuleConfirmation = "Confirmed when conflicting CL/TE headers cause a reproducible response timing anomaly that a well-formed control request does not, and the response is not an edge/CDN/WAF block"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"request-smuggling", "heavy"}
)
