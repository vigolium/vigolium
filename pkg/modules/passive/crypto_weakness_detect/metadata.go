package crypto_weakness_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "crypto-weakness-detect"
	ModuleName  = "Cryptographic Weakness Detection"
	ModuleShort = "Detects weak cryptographic patterns in HTTP traffic"
)

var (
	ModuleDesc = `**What it means:** This passive check flags weak cryptography: a PHP magic hash (0e-prefixed digits that compare as zero), an MD5/SHA1 hash beside keywords like password or secret, a padding/decryption-failure error, or a block-aligned encrypted cookie with no integrity (MAC/HMAC) value.

**How it's exploited:** A magic hash bypasses loose-comparison checks via type juggling. MD5/SHA1 hashes are cheaply cracked. A padding-oracle error lets an attacker decrypt or forge ciphertext byte by byte. An unauthenticated cookie is open to bit-flipping.

**Fix:** Use strict comparison, modern hashing (bcrypt/argon2, SHA-256+), authenticated encryption (AES-GCM or encrypt-then-HMAC), and generic errors that hide padding details.`

	ModuleConfirmation = "Confirmed when response contains identifiable cryptographic weakness patterns such as magic hashes, weak hash usage, padding oracle errors, or unprotected encrypted cookies"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cryptography", "misconfiguration", "light"}
)
