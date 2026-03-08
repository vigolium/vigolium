package crypto_weakness_detect

import "regexp"

// magicHashPattern matches PHP magic hash values (e.g., 0e462097431906509019562988736854)
// which can cause type juggling vulnerabilities in loose comparisons.
var magicHashPattern = regexp.MustCompile(`\b0[eE]\d{30,}\b`)

// weakHashPatterns detect MD5 (32 hex) and SHA1 (40 hex) hashes near sensitive keywords.
var weakHashPatterns = struct {
	md5  *regexp.Regexp
	sha1 *regexp.Regexp
}{
	md5:  regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`),
	sha1: regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`),
}

// sensitiveHashKeywords are terms that indicate a hash is used for security purposes.
var sensitiveHashKeywords = []string{
	"password", "passwd", "pass", "hash", "token", "secret",
	"auth", "session", "digest", "checksum", "signature",
}

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
