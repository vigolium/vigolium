package auth_headers_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "auth-headers-detect"
	ModuleName  = "Auth Headers Detect"
	ModuleShort = "Detects authorization headers in requests"
)

var (
	ModuleDesc = `## Description
Passively detects authorization and authentication headers in HTTP requests,
flagging endpoints that handle sensitive credentials.

## Notes
- Scans request headers for Authorization, Cookie, X-API-Key, and similar patterns
- Helps identify authentication boundaries in the application

## References
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization`

	ModuleConfirmation = "Confirmed when request contains recognized authentication headers (Authorization, Bearer tokens, API keys)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "info-disclosure", "light"}
)
