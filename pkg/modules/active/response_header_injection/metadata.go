package response_header_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "response-header-injection"
	ModuleName  = "HTTP Response Header Injection"
	ModuleShort = "Detects HTTP response header injection via CRLF in parameters"
)

var (
	ModuleDesc = `**What it means:** A request parameter is copied into the HTTP response headers without stripping carriage-return/line-feed (CRLF) characters. The scanner injected CRLF sequences plus a unique canary header into the parameter and confirmed, across multiple replays with fresh canaries, that the canary surfaced as a brand-new response header line or split the header block into the response body. This means an attacker controls part of the raw response stream.

**How it's exploited:** By submitting a value containing CRLF, an attacker injects arbitrary headers (for example a Set-Cookie for session fixation) or terminates the header block early to control the response body, enabling HTTP response splitting, cache poisoning of shared proxy caches, and script injection. When the response is served over a reused HTTP/1.1 keep-alive connection behind a pooling proxy, the scanner flags the injection as likely escalatable to Response Queue Poisoning, where other users receive the attacker-controlled response.

**Fix:** Reject or URL-encode CR and LF characters in any user input before placing it in a response header.`

	ModuleConfirmation = "Confirmed when an injected canary value with CRLF sequences appears as a new header line in the HTTP response"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"crlf", "injection", "header", "response-splitting", "moderate"}
)
