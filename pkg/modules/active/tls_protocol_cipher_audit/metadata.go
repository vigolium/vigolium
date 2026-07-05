package tls_protocol_cipher_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "tls-protocol-cipher-audit"
	ModuleName  = "TLS Protocol & Cipher Audit"
	ModuleShort = "Grades a host's TLS by negotiating deprecated protocols and weak cipher suites directly"
)

var (
	ModuleDesc = `**What it means:** The host negotiates a deprecated TLS version (1.0/1.1, retired by RFC 8996) or a weak cipher (RC4, 3DES, or static-RSA with no forward secrecy). A successful handshake at a weak setting is deterministic proof.

**How it's exploited:** TLS 1.0/1.1 carry known weaknesses and fail compliance. RC4 is broken. 3DES enables Sweet32 (CVE-2016-2183). Static-RSA gives no forward secrecy, so a future key compromise decrypts past traffic.

**Fix:** Require TLS 1.2+; remove RC4/3DES/NULL/anon/EXPORT suites; prefer ECDHE AEAD ciphers (AES-GCM, ChaCha20-Poly1305) and disable static-RSA key exchange.`

	ModuleConfirmation = "Confirmed when the module completes a TLS handshake with the host at a deprecated protocol version or weak cipher suite — re-verified with a second independent handshake before reporting"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"tls", "crypto", "transport", "misconfiguration", "moderate"}
)
