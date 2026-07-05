package cross_origin_isolation_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cross-origin-isolation-audit"
	ModuleName  = "Cross-Origin Isolation Headers Missing"
	ModuleShort = "Flags authenticated responses missing COOP/CORP cross-origin isolation headers"
)

var (
	ModuleDesc = `**What it means:** An authenticated response (it sets a session cookie or the request was authorized) does not send Cross-Origin-Opener-Policy (COOP) or Cross-Origin-Resource-Policy (CORP). These headers are the primary defense against cross-site leak (XS-Leaks) oracles.

**How it's exploited:** Without COOP, a cross-origin page keeps a window reference and can probe frame counts, navigation, and login state. Without CORP, other origins can embed the resource and read error/timing/cache oracles to infer authenticated content.

**Fix:** Send Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: same-origin (add COEP where feasible) on authenticated responses.`

	ModuleConfirmation = "Reported when a response that sets a session cookie or answers an authorized request lacks COOP and/or CORP headers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"client-side", "xs-leaks", "headers", "light"}
)
