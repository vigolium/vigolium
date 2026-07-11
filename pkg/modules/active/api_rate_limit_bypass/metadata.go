package api_rate_limit_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-rate-limit-bypass"
	ModuleName  = "API Rate Limit Bypass"
	ModuleShort = "Detects rate limiting bypass via IP spoofing headers"
)

var (
	ModuleDesc = `**What it means:** A throttled GET became successful for two distinct test identities supplied through a forwarding header. This differential is a candidate; a finding requires exhausting identity A, immediate success for identity B, and continued throttling for A and the plain request.

**How it's exploited:** An attacker rotates spoofed client-IP headers to obtain fresh rate-limit buckets.

**Fix:** Key limits from the trusted connection source and honor forwarding headers only from known proxies.`

	ModuleConfirmation = "Candidate after a body-matched 429/header/429 differential with two identities; confirmed when per-identity bucket exhaustion and rotation are demonstrated"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
