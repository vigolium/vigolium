package jwt_weak_secret

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jwt-weak-secret"
	ModuleName  = "JWT Weak Secret Detection"
	ModuleShort = "Detects JWTs with weak HMAC secrets, non-cryptographic signatures, and algorithm confusion"
)

var (
	ModuleDesc = `**What it means:** A JWT signature matches a known weak HMAC secret or is printable non-cryptographic text. Server-issued tokens form findings; client tokens and arbitrary body text remain candidates.

**How it's exploited:** An attacker who knows the signing secret forges claims such as an elevated role. Asymmetric algorithm-confusion patterns remain candidates until verifier acceptance is proven.

**Fix:** Use a high-entropy secret or managed asymmetric key and pin the accepted algorithm server-side.`

	ModuleConfirmation = "Confirmed only when an offline signature match or non-cryptographic signature is tied to response Authorization or Set-Cookie issuance; other locations remain candidates"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "cryptography", "session", "moderate"}
)
