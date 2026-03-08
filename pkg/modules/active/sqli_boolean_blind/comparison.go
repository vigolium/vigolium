package sqli_boolean_blind

import (
	"crypto/sha256"
)

// responseSignature captures key response attributes for comparison.
type responseSignature struct {
	statusCode int
	bodyLength int
	bodyHash   [32]byte
}

// newResponseSignature creates a signature from response attributes.
func newResponseSignature(statusCode int, body string) responseSignature {
	return responseSignature{
		statusCode: statusCode,
		bodyLength: len(body),
		bodyHash:   sha256.Sum256([]byte(body)),
	}
}

// isDifferent returns true if two signatures are meaningfully different.
// Used to determine if TRUE/FALSE payloads produce different responses.
func isDifferent(a, b responseSignature) bool {
	// Different status codes are a strong signal
	if a.statusCode != b.statusCode {
		return true
	}

	// Same content hash means identical responses
	if a.bodyHash == b.bodyHash {
		return false
	}

	// Check body length differential: >20% or >100 bytes
	diff := a.bodyLength - b.bodyLength
	if diff < 0 {
		diff = -diff
	}

	if diff > 100 {
		return true
	}

	// Percentage-based check (avoid division by zero)
	maxLen := a.bodyLength
	if b.bodyLength > maxLen {
		maxLen = b.bodyLength
	}
	if maxLen > 0 && float64(diff)/float64(maxLen) > 0.20 {
		return true
	}

	return false
}

// isSimilar returns true if two signatures are effectively the same response.
// Used to confirm that repeated requests produce consistent results.
func isSimilar(a, b responseSignature) bool {
	// Must have same status code
	if a.statusCode != b.statusCode {
		return false
	}

	// Identical content
	if a.bodyHash == b.bodyHash {
		return true
	}

	// Allow small variance (dynamic content like timestamps, CSRF tokens)
	diff := a.bodyLength - b.bodyLength
	if diff < 0 {
		diff = -diff
	}

	// Similar if body length difference is <5% and <50 bytes
	if diff > 50 {
		return false
	}

	maxLen := a.bodyLength
	if b.bodyLength > maxLen {
		maxLen = b.bodyLength
	}
	if maxLen > 0 && float64(diff)/float64(maxLen) > 0.05 {
		return false
	}

	return true
}
