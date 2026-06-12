package http_request_smuggling

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "http-request-smuggling"
	ModuleName  = "HTTP Request Smuggling"
	ModuleShort = "Detects HTTP request smuggling via CL.TE and TE.CL desync"
)

var (
	ModuleDesc = `**What it means:** The site sits behind a front-end server or proxy that disagrees with the back-end about where one HTTP request ends and the next begins. The scanner sent requests with conflicting Content-Length and Transfer-Encoding framing (CL.TE, TE.CL, and TE.TE obfuscation variants) and observed a reproducible response-timing anomaly consistent with the back-end desynchronizing while it waits for smuggled bytes. This is a probable request-smuggling (HTTP desync) condition, though the result is timing-inferred and reported as suspect rather than proven.

**How it's exploited:** An attacker prepends crafted bytes to a victim's pipelined request to poison the shared connection, hijacking other users' requests, stealing session cookies or credentials, bypassing front-end access controls and WAF rules, or poisoning the response cache to serve malicious content to everyone.

**Fix:** Make the front-end and back-end agree on request framing: reject ambiguous requests carrying both Content-Length and Transfer-Encoding, normalize or strip Transfer-Encoding at the edge, prefer HTTP/2 end-to-end, and keep proxy and server software patched.`

	ModuleConfirmation = "Confirmed when conflicting CL/TE headers cause a reproducible response timing anomaly that a well-formed control request does not, and the response is not an edge/CDN/WAF block"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"request-smuggling", "heavy"}
)
