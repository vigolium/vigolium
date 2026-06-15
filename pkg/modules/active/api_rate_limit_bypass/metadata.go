package api_rate_limit_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-rate-limit-bypass"
	ModuleName  = "API Rate Limit Bypass"
	ModuleShort = "Detects rate limiting bypass via IP spoofing headers"
)

var (
	ModuleDesc = `**What it means:** The endpoint enforces rate limiting (HTTP 429 after a burst) but keys the limit on a client-supplied IP header, not the true connection source. A spoofed X-Forwarded-For or X-Real-IP makes the server treat each request as new.

**How it's exploited:** An attacker rotates a forged IP header to reset the counter and send unlimited traffic, defeating throttling meant to stop credential stuffing and brute force. Confirmed differentially: a plain request stays 429 while the spoofed one succeeds.

**Fix:** Derive the rate-limit identity from the trusted connection source, and only honor forwarding headers from known proxies.`

	ModuleConfirmation = "Confirmed when the server enforces rate limiting (429 response) but accepts requests with IP spoofing headers, indicating bypassable rate limiting"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
