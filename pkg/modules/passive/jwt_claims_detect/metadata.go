package jwt_claims_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jwt-claims-detect"
	ModuleName  = "JWT Claim Analyzer"
	ModuleShort = "Analyzes JWT claims for security misconfigurations"
)

var (
	ModuleDesc = `**What it means:** A JSON Web Token observed in this traffic (in an Authorization Bearer header, a cookie, or a response body) carries claim or header settings that weaken its security. The scanner decodes the header and payload without verifying the signature and flags issues such as alg=none (no signature verification), a missing exp claim (token never expires), a long-lived token (lifetime over 24 hours), missing iss or aud claims, or privileged claims like admin=true, is_admin=true, or an admin/superuser role.

**How it's exploited:** With alg=none an attacker can forge a valid token by stripping the signature, and embedded privileged claims reveal which fields to tamper with to escalate to admin. Missing or overly long expiration means a stolen token stays usable indefinitely, and missing iss/aud lets a token meant for one service be replayed against another.

**Fix:** Require a strong signature algorithm and reject alg=none, set short exp lifetimes, validate iss and aud on every request, and derive privilege from server-side state rather than trusting client-held claims.`

	ModuleConfirmation = "Confirmed when JWT claims contain security misconfigurations"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "cryptography", "light"}
)
