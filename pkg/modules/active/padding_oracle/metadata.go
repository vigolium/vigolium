package padding_oracle

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "padding-oracle"
	ModuleName  = "CBC Padding Oracle"
	ModuleShort = "Confirms a CBC padding oracle by flipping ciphertext bytes and observing a distinct, reproducible padding-error differential"
)

var (
	ModuleDesc = `**What it means:** The application decrypts an attacker-supplied CBC ciphertext (a cookie or token) and reveals, through a distinct error or response, whether the PKCS#7 padding was valid. This confirmer flips ciphertext bytes across two rounds to prove the oracle.

**How it's exploited:** An attacker uses the padding oracle to decrypt the ciphertext byte-by-byte, and can also forge valid ciphertext, tampering with sessions or tokens without the key.

**Fix:** Use authenticated encryption (AES-GCM) or encrypt-then-MAC, verify integrity before decrypting, and return identical generic errors for all decryption failures.`

	ModuleConfirmation = "Confirmed when block-aligned ciphertext mutations reproducibly trigger a padding-specific error that is absent from stable baselines and distinct from a malformed-encoding control, across two independent rounds (bit positions)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cryptography", "injection", "heavy"}
)
