package httpmsg

// encoding.go - Encoding/decoding utilities for URL encoding, Base64, and string/bytes conversion

import (
	"encoding/base64"
	"errors"
)

// UrlEncode encodes a string for safe use in URLs.
// Delegates to EncodeQueryValue in query_parser.go.
//
// Example:
//
//	UrlEncode("hello world")   // Returns "hello+world"
//	UrlEncode("a=b&c=d")       // Returns "a%3Db%26c%3Dd"
//
// Parameters:
//   - s: String to encode
//
// Returns:
//   - URL-encoded string
func UrlEncode(s string) string {
	return EncodeQueryValue(s)
}

// UrlDecode decodes a URL-encoded string.
// Delegates to DecodeQueryValue in query_parser.go.
//
// Example:
//
//	UrlDecode("hello+world")      // Returns "hello world"
//	UrlDecode("a%3Db%26c%3Dd")    // Returns "a=b&c=d"
//
// Parameters:
//   - s: URL-encoded string to decode
//
// Returns:
//   - Decoded string
func UrlDecode(s string) string {
	return DecodeQueryValue(s)
}

// UrlEncodeBytes encodes byte array for safe use in URLs.
//
// Algorithm:
//  1. Loop through each byte
//  2. Encode special characters (#, %, &, +, :, ;, =, ?, @) as %XX
//  3. Encode space as '+'
//  4. Leave other characters as-is
//
// Example:
//
//	UrlEncodeBytes([]byte("hello world"))   // Returns []byte("hello+world")
//	UrlEncodeBytes([]byte("a=b&c=d"))       // Returns []byte("a%3Db%26c%3Dd")
//
// Parameters:
//   - data: Byte array to encode
//
// Returns:
//   - URL-encoded byte array
func UrlEncodeBytes(data []byte) []byte {
	if data == nil {
		return nil
	}

	encoded := EncodeQueryValue(string(data))
	return []byte(encoded)
}

// UrlDecodeBytes decodes a URL-encoded byte array.
//
// Algorithm:
//  1. Loop through each byte
//  2. Convert '+' to space (byte 32)
//  3. Decode %XX hex sequences
//  4. Handle %uXXXX unicode sequences (4 hex digits)
//  5. Copy other bytes as-is
//
// Example:
//
//	UrlDecodeBytes([]byte("hello+world"))      // Returns []byte("hello world")
//	UrlDecodeBytes([]byte("a%3Db%26c%3Dd"))    // Returns []byte("a=b&c=d")
//
// Parameters:
//   - data: URL-encoded byte array to decode
//
// Returns:
//   - Decoded byte array
//   - Error if decoding fails (for API consistency, though current implementation doesn't error)
func UrlDecodeBytes(data []byte) ([]byte, error) {
	if data == nil {
		return nil, nil
	}

	decoded := DecodeQueryValue(string(data))
	return []byte(decoded), nil
}

// Base64Encode encodes a string to Base64.
//
// Example:
//
//	Base64Encode("hello")      // Returns "aGVsbG8="
//	Base64Encode("hello world") // Returns "aGVsbG8gd29ybGQ="
//
// Parameters:
//   - s: String to encode
//
// Returns:
//   - Base64-encoded string
func Base64Encode(s string) string {
	return Base64EncodeBytes([]byte(s))
}

// Base64EncodeBytes encodes bytes to Base64 string.
//
// Example:
//
//	Base64EncodeBytes([]byte("hello"))      // Returns "aGVsbG8="
//	Base64EncodeBytes([]byte{0x01, 0x02})   // Returns "AQI="
//
// Parameters:
//   - data: Byte array to encode
//
// Returns:
//   - Base64-encoded string
func Base64EncodeBytes(data []byte) string {
	if data == nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes a Base64-encoded string.
//
// Example:
//
//	Base64Decode("aGVsbG8=")         // Returns []byte("hello"), nil
//	Base64Decode("aGVsbG8gd29ybGQ=") // Returns []byte("hello world"), nil
//	Base64Decode("invalid!")         // Returns nil, error
//
// Parameters:
//   - s: Base64-encoded string to decode
//
// Returns:
//   - Decoded bytes
//   - Error if decoding fails
func Base64Decode(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid base64 data")
	}
	return decoded, nil
}

// Base64DecodeBytes decodes Base64-encoded bytes.
//
// Example:
//
//	Base64DecodeBytes([]byte("aGVsbG8="))         // Returns []byte("hello"), nil
//	Base64DecodeBytes([]byte("aGVsbG8gd29ybGQ=")) // Returns []byte("hello world"), nil
//
// Parameters:
//   - data: Base64-encoded byte array to decode
//
// Returns:
//   - Decoded bytes
//   - Error if decoding fails
func Base64DecodeBytes(data []byte) ([]byte, error) {
	if data == nil {
		return nil, nil
	}

	return Base64Decode(string(data))
}

// StringToBytes converts a string to byte array.
//
// Algorithm:
//  1. Create byte array with length = string length
//  2. Loop through each character
//  3. Cast each char to byte
//  4. Store in byte array
//
// Note: This truncates Unicode to single bytes.
// For proper Unicode handling, use []byte(s) directly in production code.
//
// Example:
//
//	StringToBytes("hello")   // Returns []byte{104, 101, 108, 108, 111}
//	StringToBytes("")        // Returns []byte{}
//
// Parameters:
//   - s: String to convert
//
// Returns:
//   - Byte array
func StringToBytes(s string) []byte {
	if s == "" {
		return []byte{}
	}

	// Simple byte-by-byte conversion (for ASCII, same as []byte(s))
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		result[i] = byte(s[i])
	}
	return result
}

// BytesToString converts byte array to string.
//
// Note: For proper UTF-8 handling, use string(b) directly in production code.
//
// Example:
//
//	BytesToString([]byte{104, 101, 108, 108, 111})   // Returns "hello"
//	BytesToString([]byte{})                           // Returns ""
//
// Parameters:
//   - b: Byte array to convert
//
// Returns:
//   - String
func BytesToString(b []byte) string {
	if b == nil {
		return ""
	}

	return string(b)
}
