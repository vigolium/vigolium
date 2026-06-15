package jwt_claims_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jwt-claims-detect"
	ModuleName  = "JWT Claim Analyzer"
	ModuleShort = "Analyzes JWT claims for security misconfigurations"
)

var (
	ModuleDesc = `**What it means:** A JWT seen in traffic (Bearer header, cookie, or body) carries weak settings. The check decodes header and payload and flags alg=none, a missing or over-24-hour exp, missing iss or aud, or privileged claims like admin=true.

**How it's exploited:** With alg=none an attacker forges a token by stripping the signature; privileged claims show which fields to tamper with to escalate. Long exp keeps a stolen token usable; missing iss/aud lets it be replayed against another service.

**Fix:** Reject alg=none, require a strong algorithm, set short exp, validate iss and aud, and derive privilege from server-side state.`

	ModuleConfirmation = "Confirmed when JWT claims contain security misconfigurations"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "cryptography", "light"}
)
