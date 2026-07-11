package crypto_weakness_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "crypto-weakness-detect"
	ModuleName  = "Cryptographic Weakness Detection"
	ModuleShort = "Detects weak cryptographic patterns in HTTP traffic"
)

var (
	ModuleDesc = `**What it means:** This passive check records cryptographic indicators, not proof: magic-hash or legacy credential-digest values, disclosed padding/decryption errors, and opaque block-aligned session cookies. Wire shape can't prove a cookie lacks integrity, and one error can't prove an oracle.

**How it's exploited:** A magic hash bypasses loose comparisons via type juggling. MD5/SHA1 hashes are cheaply cracked. A padding-oracle error lets an attacker decrypt or forge ciphertext byte by byte. Unauthenticated cookies allow bit-flipping.

**Fix:** Use strict comparison, modern hashing (bcrypt/argon2, SHA-256+), authenticated encryption (AES-GCM or encrypt-then-HMAC), and generic errors that hide padding details.`

	ModuleConfirmation = "Passive indicators are observations/candidates only; confirmation requires code-level algorithm evidence or repeatable active comparison/ciphertext-mutation behavior"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cryptography", "misconfiguration", "light"}
)
