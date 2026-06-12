package api_rate_limit_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-rate-limit-bypass"
	ModuleName  = "API Rate Limit Bypass"
	ModuleShort = "Detects rate limiting bypass via IP spoofing headers"
)

var (
	ModuleDesc = `**What it means:** The endpoint enforces rate limiting (it returns HTTP 429 after a burst of requests) but that limit is keyed on a client-supplied IP header rather than the true connection source. Sending a spoofed IP header such as X-Forwarded-For or X-Real-IP makes the server treat each request as a brand-new client, so the protection can be defeated at will.

**How it's exploited:** An attacker rotates a forged IP header on every request to reset the per-client counter and send unlimited traffic, neutralizing throttling that was meant to stop credential stuffing, brute force, OTP/token guessing, scraping, and resource-exhaustion abuse against the API. The scanner confirms this with a differential check: a plain request stays 429 while the same request carrying the spoofed header succeeds again.

**Fix:** Derive the rate-limit client identity from the trusted connection source or an authenticated identity, and only honor forwarding headers from known, trusted proxies.`

	ModuleConfirmation = "Confirmed when the server enforces rate limiting (429 response) but accepts requests with IP spoofing headers, indicating bypassable rate limiting"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
