package crypto_weakness_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "crypto-weakness-detect"
	ModuleName  = "Cryptographic Weakness Detection"
	ModuleShort = "Detects weak cryptographic patterns in HTTP traffic"
)

var (
	ModuleDesc = `**What it means:** This passive check flags signs of weak or misused cryptography in HTTP responses and cookies: a PHP "magic hash" (0e-prefixed digit string that loosely compares as zero), an MD5 or SHA1 hash next to security keywords like password, token, or secret, an error message leaking a padding/decryption failure, or an encrypted, block-aligned cookie with no companion integrity (MAC/HMAC) value. These point to hashing or encryption choices an attacker can subvert.

**How it's exploited:** A magic hash can bypass loose-comparison password or token checks via type juggling. MD5/SHA1 password or signature hashes are cheaply cracked or collided. A padding-oracle error message lets an attacker decrypt or forge ciphertext byte by byte (POODLE-style). An unauthenticated encrypted cookie is open to bit-flipping that mutates the underlying plaintext without detection, potentially escalating privileges or tampering with session state.

**Fix:** Use constant-time/strict comparison, modern hashing (bcrypt/argon2 for passwords, SHA-256+ for integrity), authenticated encryption (AES-GCM or encrypt-then-HMAC) for cookies, and return generic errors that never reveal padding or decryption details.`

	ModuleConfirmation = "Confirmed when response contains identifiable cryptographic weakness patterns such as magic hashes, weak hash usage, padding oracle errors, or unprotected encrypted cookies"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cryptography", "misconfiguration", "light"}
)
