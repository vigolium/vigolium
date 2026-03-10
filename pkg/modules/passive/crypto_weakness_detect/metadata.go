package crypto_weakness_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "crypto-weakness-detect"
	ModuleName  = "Cryptographic Weakness Detection"
	ModuleShort = "Detects weak cryptographic patterns in HTTP traffic"
)

var (
	ModuleDesc = `## Description
Detects cryptographic weaknesses in HTTP responses and cookies, including PHP magic hashes,
weak hash algorithms near sensitive contexts, padding oracle indicators, and encrypted cookies
without integrity protection (MAC).

## Notes
- Analyzes both request cookies and response headers/body
- Checks for MD5/SHA1 usage near password, token, or hash keywords
- Detects padding oracle error messages that may enable ciphertext manipulation
- Identifies encrypted cookie values that lack HMAC integrity verification

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/
- https://www.whitehatsec.com/blog/magic-hashes/`

	ModuleConfirmation = "Confirmed when response contains identifiable cryptographic weakness patterns such as magic hashes, weak hash usage, padding oracle errors, or unprotected encrypted cookies"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"cryptography", "misconfiguration", "light"}
)
