package crypto_weakness_detect

import "regexp"

// cbcTechTag is the technology tag this passive module publishes when it detects
// a CBC-shaped ciphertext (an opaque block-aligned session cookie) or a disclosed
// padding/decryption error. The active padding-oracle module is hard-gated on it.
const cbcTechTag = "crypto-cbc"

// magicHashFieldPattern matches PHP magic hash values (e.g.,
// 0e462097431906509019562988736854) that appear in a structured
// password/credential/digest field, where they can cause type juggling
// vulnerabilities in loose comparisons.
var magicHashFieldPattern = regexp.MustCompile(`(?i)["']?([a-z0-9_]*(?:password|passwd|credential|digest|hash)[a-z0-9_]*)["']?\s*[:=]\s*["']?(0[eE]\d{30,})\b`)

// weakHashFieldPattern matches MD5 (32 hex) and SHA1 (40 hex) digests exposed in
// a structured password/credential field.
var weakHashFieldPattern = regexp.MustCompile(`(?i)["']?([a-z0-9_]*(?:password|passwd|credential)[a-z0-9_]*(?:hash|digest)?)["']?\s*[:=]\s*["']?([a-f0-9]{32}|[a-f0-9]{40})\b`)

// paddingOraclePatterns match error messages indicative of padding oracle vulnerabilities.
var paddingOraclePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)BadPaddingException`),
	regexp.MustCompile(`(?i)Invalid\s+padding`),
	regexp.MustCompile(`(?i)padding\s+is\s+invalid`),
	regexp.MustCompile(`(?i)Padding\s+error`),
	regexp.MustCompile(`(?i)PKCS[#57]\s+.*(?:error|invalid|bad)`),
	regexp.MustCompile(`(?i)decryption\s+(?:failed|error)`),
	regexp.MustCompile(`(?i)CryptographicException`),
	regexp.MustCompile(`(?i)OpenSSL.*(?:bad\s+decrypt|padding)`),
}

// etagPattern matches ETag header values (which legitimately contain hex strings).
var etagPattern = regexp.MustCompile(`^(?:W/)?"[^"]*"$`)

// uuidPattern matches UUID format strings.
var uuidPattern = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

// cssColorPattern matches CSS hex color codes (#abc, #aabbcc).
var cssColorPattern = regexp.MustCompile(`^#[a-fA-F0-9]{3,8}$`)

// isLikelyFalsePositiveHash checks if a hex string is an ETag, UUID, or CSS color.
func isLikelyFalsePositiveHash(value string) bool {
	if etagPattern.MatchString(value) {
		return true
	}
	if uuidPattern.MatchString(value) {
		return true
	}
	if cssColorPattern.MatchString(value) {
		return true
	}
	return false
}
