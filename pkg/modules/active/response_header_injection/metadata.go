package response_header_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "response-header-injection"
	ModuleName  = "HTTP Response Header Injection"
	ModuleShort = "Detects HTTP response header injection via CRLF in parameters"
)

var (
	ModuleDesc = `## Description
Detects HTTP response header injection vulnerabilities where user-supplied parameter values
are copied into response headers (e.g. Set-Cookie, Location). By injecting CRLF sequences,
an attacker can inject arbitrary HTTP headers or break into the response body.

## Impact
- HTTP response splitting: inject arbitrary headers or body content
- Cache poisoning: poison proxy caches with attacker-controlled responses
- Cross-site scripting: inject JavaScript via crafted response body
- Session fixation: inject Set-Cookie headers

## References
- CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
- CAPEC-34: HTTP Response Splitting
- https://owasp.org/www-community/attacks/HTTP_Response_Splitting`

	ModuleConfirmation = "Confirmed when an injected canary value with CRLF sequences appears as a new header line in the HTTP response"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"crlf", "injection", "header", "response-splitting", "moderate"}
)
