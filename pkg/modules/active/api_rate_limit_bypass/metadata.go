package api_rate_limit_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-rate-limit-bypass"
	ModuleName  = "API Rate Limit Bypass"
	ModuleShort = "Detects rate limiting bypass via IP spoofing headers"
)

var (
	ModuleDesc = `## Description
Detects API rate limiting that can be bypassed using IP spoofing headers such as
X-Forwarded-For, X-Real-IP, and similar headers. First triggers rate limiting by
sending rapid requests, then tests whether bypass headers circumvent the limit.

## Notes
- Runs once per host with internal deduplication
- Sends up to 10 rapid requests to trigger rate limiting
- Tests 8 different IP spoofing header variations
- Only reports when rate limiting is confirmed then bypassed

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema
- https://portswigger.net/web-security/authentication/password-based`

	ModuleConfirmation = "Confirmed when the server enforces rate limiting (429 response) but accepts requests with IP spoofing headers, indicating bypassable rate limiting"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
