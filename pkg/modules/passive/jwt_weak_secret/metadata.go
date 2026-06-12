package jwt_weak_secret

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "jwt-weak-secret"
	ModuleName  = "JWT Weak Secret Detection"
	ModuleShort = "Detects JWTs with weak HMAC secrets, non-cryptographic signatures, and algorithm confusion"
)

var (
	ModuleDesc = `**What it means:** A JSON Web Token used by this application is signed with a weak, guessable, or non-cryptographic secret. JWTs carry identity and authorization claims, so anyone who recovers the signing key can mint tokens the server will trust. This module passively pulls JWTs from Authorization Bearer headers, cookies, and response bodies, then verifies the signature offline against an embedded list of ~104K known weak secrets without sending extra traffic.

**How it's exploited:** Once the secret is known, an attacker forges a token with an elevated identity or role (for example admin) and signs it with the recovered key, gaining account takeover or privilege escalation. The module also flags tokens whose signature decodes to plain ASCII (trivially forgeable) and asymmetric-algorithm tokens that may permit HMAC algorithm-confusion (CVE-2015-9235), where a forged HS256 token is verified using the public key as the HMAC secret.

**Fix:** Sign JWTs with a long, random, high-entropy secret (or a managed asymmetric key) and pin the accepted algorithm server-side so the alg header cannot downgrade verification.`

	ModuleConfirmation = "Confirmed when a JWT HMAC signature matches a known weak secret"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "cryptography", "session", "moderate"}
)
