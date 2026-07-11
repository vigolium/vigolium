package jwt_claims_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jwt-claims-detect"
	ModuleName  = "JWT Claim Analyzer"
	ModuleShort = "Analyzes JWT claims for security misconfigurations"
)

var (
	ModuleDesc = `**What it means:** A JWT seen in traffic carries a security-relevant configuration or claim. Missing/long expiry, absent issuer/audience, and privilege fields are observations. alg=none is a candidate until a forged token is actively accepted.

**How it's exploited:** With alg=none an attacker forges a token by stripping the signature; privileged claims show which fields to tamper with to escalate. Long exp keeps a stolen token usable; missing iss/aud lets it be replayed against another service.

**Fix:** Reject alg=none, require a strong algorithm, set short exp, validate iss and aud, and derive privilege from server-side state.`

	ModuleConfirmation = "Observation for claim hygiene; alg=none is a candidate only, and confirmation requires a forged-token acceptance and authorization differential"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "cryptography", "light"}
)
