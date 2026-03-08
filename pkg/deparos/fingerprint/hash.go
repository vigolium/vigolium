package fingerprint

import (
	"hash/crc32"
	"sort"
	"strings"
)

// HashString computes CRC32 hash of a string
// Maps to Burp's fmx.java single value hashing (Lines 5-52)
func HashString(s string) uint32 {
	if s == "" {
		return 0
	}
	return crc32.ChecksumIEEE([]byte(s))
}

// HashStrings computes accumulated CRC32 hash of multiple strings
// Maps to Burp's dis.java CRC32 accumulator (Lines 5-59)
// Strings are processed in order (not sorted)
func HashStrings(strings []string) uint32 {
	if len(strings) == 0 {
		return 0
	}

	var hash uint32
	for _, s := range strings {
		if s != "" {
			hash = accumulateCRC32(hash, []byte(s))
		}
	}
	return hash
}

// HashStringSet computes CRC32 hash of string set (sorted for consistency)
// Maps to Burp's set-based hashing for unique values
// Used for cookie names, class names, etc.
func HashStringSet(strings []string) uint32 {
	if len(strings) == 0 {
		return 0
	}

	// Create sorted copy for consistent hashing
	sorted := make([]string, len(strings))
	copy(sorted, strings)
	sort.Strings(sorted)

	var hash uint32
	for _, s := range sorted {
		if s != "" {
			hash = accumulateCRC32(hash, []byte(s))
		}
	}
	return hash
}

// HashBytes computes CRC32 hash of bytes
func HashBytes(b []byte) uint32 {
	if len(b) == 0 {
		return 0
	}
	return crc32.ChecksumIEEE(b)
}

// accumulateCRC32 accumulates CRC32 hash
// Maps to Burp's dis.java:accumulate() (Lines 20-35)
// Combines existing hash with new data using XOR and addition
func accumulateCRC32(currentHash uint32, data []byte) uint32 {
	// Compute CRC32 of new data
	newHash := crc32.ChecksumIEEE(data)

	// Accumulate: XOR and rotate
	// This matches Burp's accumulation algorithm
	accumulated := currentHash ^ newHash
	accumulated = rotateLeft(accumulated, 1)

	return accumulated
}

// rotateLeft rotates bits left by n positions
func rotateLeft(value uint32, n uint) uint32 {
	return (value << n) | (value >> (32 - n))
}

// ParseContentType extracts content type without charset
// Maps to Burp's content-type parsing in ad1.java
func ParseContentType(contentType string) string {
	if contentType == "" {
		return ""
	}

	// Split on semicolon to remove charset
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return ""
	}

	// Return just the MIME type, trimmed
	return strings.TrimSpace(parts[0])
}

// ExtractCookieNames extracts cookie names from Set-Cookie headers
// Maps to Burp's cookie extraction in ad1.java
func ExtractCookieNames(setCookieHeaders []string) []string {
	if len(setCookieHeaders) == 0 {
		return nil
	}

	names := make([]string, 0, len(setCookieHeaders))
	for _, header := range setCookieHeaders {
		// Cookie format: name=value; attributes
		parts := strings.Split(header, "=")
		if len(parts) > 0 {
			name := strings.TrimSpace(parts[0])
			if name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

// TruncateBytes returns first n bytes of data
// Used for InitialContent and LimitedBodyContent attributes
func TruncateBytes(data []byte, maxBytes int) []byte {
	if len(data) <= maxBytes {
		return data
	}
	return data[:maxBytes]
}

// Constants for content truncation
// Maps to Burp's content size limits
const (
	// InitialContentBytes = 1024  // First 1KB for InitialContent
	// LimitedContentBytes = 10240 // First 10KB for LimitedBodyContent
	// Ta nên để ngắn thế này để cho trường hợp là ngắn có thể match được. Ta có trường hợp json ngắn chỉ có 2 static attributes là content-type: json và status-code: 200.
	// Cái này ta đặt thấp thì sẽ thêm được 1 phần thế này: `{"endpoints":{"health":"/health","liveness":"/live","readiness":"/ready"},"message":"Webhook receive`
	// Default 1024 quá dài
	InitialContentBytes = 100  // First 100 bytes for InitialContent
	LimitedContentBytes = 1024 // First 10KB for LimitedBodyContent
	LastContentBytes    = 100  // Last 100 bytes for LastContent
)
