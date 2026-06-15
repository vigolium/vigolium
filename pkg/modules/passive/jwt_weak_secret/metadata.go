package jwt_weak_secret

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jwt-weak-secret"
	ModuleName  = "JWT Weak Secret Detection"
	ModuleShort = "Detects JWTs with weak HMAC secrets, non-cryptographic signatures, and algorithm confusion"
)

var (
	ModuleDesc = `**What it means:** A JWT used by this app is signed with a weak or guessable secret, so anyone who recovers the key can mint tokens the server trusts. The check verifies signatures offline against ~104K known weak secrets.

**How it's exploited:** With the secret known, an attacker forges a token with an elevated role for account takeover. The check also flags signatures decoding to plain ASCII and asymmetric tokens vulnerable to HMAC algorithm-confusion (CVE-2015-9235).

**Fix:** Sign JWTs with a long, high-entropy random secret or managed asymmetric key, and pin the algorithm server-side so alg cannot downgrade verification.`

	ModuleConfirmation = "Confirmed when a JWT HMAC signature matches a known weak secret"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "cryptography", "session", "moderate"}
)
