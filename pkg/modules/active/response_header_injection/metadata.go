package response_header_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "response-header-injection"
	ModuleName  = "HTTP Response Header Injection"
	ModuleShort = "Detects HTTP response header injection via CRLF in parameters"
)

var (
	ModuleDesc = `**What it means:** A request parameter is copied into the HTTP response headers without stripping CRLF characters. An injected canary surfaced as a new header line or split the header block into the body, so an attacker controls part of the response.

**How it's exploited:** A CRLF-laden value injects arbitrary headers (such as a Set-Cookie) or ends the header block early to control the body, enabling response splitting, cache poisoning, and script injection. Behind a pooling proxy it can become Response Queue Poisoning.

**Fix:** Reject or URL-encode CR and LF in user input before using it in a response header.`

	ModuleConfirmation = "Confirmed when an injected canary value with CRLF sequences appears as a new header line in the HTTP response"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"crlf", "injection", "header", "response-splitting", "moderate"}
)
