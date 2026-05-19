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

## References
- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/research/http-desync-attacks`

	ModuleConfirmation = "Confirmed when conflicting CL/TE headers cause measurable response timing differences indicating request desync"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"request-smuggling", "heavy"}
)
