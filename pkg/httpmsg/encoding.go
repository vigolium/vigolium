package httpmsg

// encoding.go - Encoding/decoding utilities ported from Burp Suite
// Ported from: burp/d4n.java IExtensionHelpers implementation (lines 51-262)
//              net/portswigger/nc.java (URL encoding methods, lines 12-131)
//              net/portswigger/kh.java (Base64 encoding, lines 49-50)
//              net/portswigger/h9.java (String/bytes conversion, lines 8-45)

import (
	"encoding/base64"
	"errors"
)

// UrlEncode encodes a string for safe use in URLs.
// Ported from: d4n.java urlEncode(String) method (line 93)
//
//	Delegates to: d4n.java urlEncode(byte[]) (line 79) -> nc.j() (line 66)
//
// Implementation: Delegates to EncodeQueryValue in query_parser.go
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
	// d4n.java line 93-98: urlEncode(String) -> bytesToString(urlEncode(stringToBytes(var1)))
	// The underlying implementation uses nc.j() which is loop-based encoding
	// We delegate to our existing EncodeQueryValue which implements the same logic
	return EncodeQueryValue(s)
}

// UrlDecode decodes a URL-encoded string.
// Ported from: d4n.java urlDecode(String) method (line 65)
//
//	Delegates to: d4n.java urlDecode(byte[]) (line 51) -> nc.c() (line 12)
//
// Implementation: Delegates to DecodeQueryValue in query_parser.go
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
	// d4n.java line 65-70: urlDecode(String) -> bytesToString(urlDecode(stringToBytes(var1)))
	// The underlying implementation uses nc.c() which handles %XX and + decoding
	// We delegate to our existing DecodeQueryValue which implements the same logic
	return DecodeQueryValue(s)
}

// UrlEncodeBytes encodes byte array for safe use in URLs.
// Ported from: d4n.java urlEncode(byte[]) method (line 79)
//
//	Delegates to: nc.j() (line 66)
//
// Algorithm (from nc.j lines 66-131):
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

	// Convert to string, encode, and convert back
	// This matches d4n.java behavior at line 98: bytesToString(urlEncode(...))
	encoded := EncodeQueryValue(string(data))
	return []byte(encoded)
}

// UrlDecodeBytes decodes a URL-encoded byte array.
// Ported from: d4n.java urlDecode(byte[]) method (line 51)
//
//	Delegates to: nc.c() (line 12)
//
// Algorithm (from nc.c lines 12-64):
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

	// Convert to string, decode, and convert back
	// This matches d4n.java behavior at line 70: bytesToString(urlDecode(...))
	decoded := DecodeQueryValue(string(data))
	return []byte(decoded), nil
}

// Base64Encode encodes a string to Base64.
// Ported from: d4n.java base64Encode(String) method (line 149)
//
//	Delegates to: d4n.java base64Encode(byte[]) (line 135) -> nc.p() (line 429)
//	nc.p() calls: kh.b() which uses standard Base64 encoding
//
// Uses: Go's encoding/base64 standard library (equivalent to java.util.Base64)
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
	// d4n.java line 149-154: base64Encode(String) -> base64Encode(stringToBytes(var1))
	// h9.a() converts string to bytes by casting each char to byte (line 30-45)
	// kh.b() performs standard Base64 encoding
	return Base64EncodeBytes([]byte(s))
}

// Base64EncodeBytes encodes bytes to Base64 string.
// Ported from: d4n.java base64Encode(byte[]) method (line 135)
//
//	Delegates to: nc.p() (line 429) -> kh.b() (line 49)
//
// Uses: Go's encoding/base64.StdEncoding (equivalent to java.util.Base64)
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

	// nc.p() line 429-430: returns kh.b(var0) which does standard Base64 encoding
	// kh.b() uses custom Base64 implementation but follows standard Base64 spec
	// We can use Go's standard library encoding/base64
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes a Base64-encoded string.
// Ported from: d4n.java base64Decode(String) method (line 121)
//
//	Delegates to: d4n.java base64Decode(byte[]) (line 107) -> nc.n() (line 425)
//	nc.n() calls: kh.a() which uses standard Base64 decoding
//
// Uses: Go's encoding/base64 standard library (equivalent to java.util.Base64)
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

	// d4n.java line 121-126: base64Decode(String) -> base64Decode(stringToBytes(var1))
	// nc.n() line 425-426: returns kh.a(var0) which does standard Base64 decoding
	// On error, d4n.java throws IllegalArgumentException "Invalid data" (line 130)
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid base64 data")
	}
	return decoded, nil
}

// Base64DecodeBytes decodes Base64-encoded bytes.
// Ported from: d4n.java base64Decode(byte[]) method (line 107)
//
//	Delegates to: nc.n() (line 425) -> kh.a()
//
// Uses: Go's encoding/base64 standard library (equivalent to java.util.Base64)
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

	// d4n.java line 107-112: base64Decode(byte[]) calls nc.n()
	// nc.n() line 425-426: returns kh.a(var0) for Base64 decoding
	return Base64Decode(string(data))
}

// StringToBytes converts a string to byte array.
// Ported from: d4n.java stringToBytes() method (line 237)
//
//	Delegates to: h9.a(String) (line 30)
//
// Algorithm (from h9.a lines 30-45):
//  1. Create byte array with length = string length
//  2. Loop through each character
//  3. Cast each char to byte: (byte)var0.charAt(var4)
//  4. Store in byte array
//
// Note: This implements Burp's byte conversion which truncates Unicode to single bytes.
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

	// h9.a() line 30-45: Creates byte array and casts each char to byte
	// In Go, []byte(s) does UTF-8 encoding, but for ASCII it's the same
	// For Burp compatibility, we use simple conversion
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		result[i] = byte(s[i])
	}
	return result
}

// BytesToString converts byte array to string.
// Ported from: d4n.java bytesToString() method (line 251)
//
//	Delegates to: h9.a(byte[]) (line 8)
//
// Algorithm (from h9.a lines 8-28):
//  1. Create byte array with double the size (for UTF-16 encoding)
//  2. Copy input bytes to even positions (2*i+1)
//  3. Convert using UTF-16 encoding
//  4. This results in single-byte to char conversion
//
// Note: This implements Burp's byte conversion. For proper UTF-8 handling,
// use string(b) directly in production code.
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

	// h9.a() line 8-28: Uses UTF-16 encoding trick to convert bytes to string
	// In Go, string(b) interprets bytes as UTF-8
	// For Burp compatibility (single-byte chars), simple conversion works
	return string(b)
}
