package httpmsg

// string_utils.go - String utility functions
// Ported from: Utilities.java (string operations)
//
// This file contains:
// - Exported: BytesToHexString, FilterString, EncodeBytesAbove7F
// - Internal: randomString, generateCanary, mangle

import (
	"sync"
	"time"
)

// ==================== EXPORTED FUNCTIONS ====================

// BytesToHexString converts bytes to hex string (space-separated).
// Ported from: Utilities.java bytesToHexString() (lines 497-503)
//
// Algorithm:
//  1. Loop through bytes
//  2. Convert each byte to 2-digit hex
//  3. Join with spaces
//
// Parameters:
//   - data: Byte array to convert
//
// Returns:
//   - Hex string with space separators (e.g., "48 65 6c 6c 6f")
//
// Example:
//
//	hex := BytesToHexString([]byte("Hello"))  // "48 65 6c 6c 6f"
func BytesToHexString(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Hex characters lookup table
	hexChars := []byte("0123456789abcdef")

	// Calculate result size: 2 hex chars + space per byte, minus trailing space
	resultLen := len(data)*3 - 1
	result := make([]byte, resultLen)

	for i := 0; i < len(data); i++ {
		b := data[i]
		pos := i * 3

		// High nibble
		result[pos] = hexChars[b>>4]
		// Low nibble
		result[pos+1] = hexChars[b&0x0F]

		// Add space (except after last byte)
		if i < len(data)-1 {
			result[pos+2] = ' '
		}
	}

	return string(result)
}

// FilterString keeps only characters in safeChars.
// Ported from: Utilities.java filter() (lines 239-249)
//
// Algorithm:
//  1. Loop through input characters
//  2. Check if character is in safeChars
//  3. Keep only matching characters
//
// Parameters:
//   - input: String to filter
//   - safeChars: String containing allowed characters
//
// Returns:
//   - Filtered string containing only safe characters
//
// Example:
//
//	filtered := FilterString("abc123!@#", "abcdefghijklmnopqrstuvwxyz")
//	// Returns "abc"
func FilterString(input, safeChars string) string {
	if input == "" {
		return ""
	}
	if safeChars == "" {
		return ""
	}

	result := make([]byte, 0, len(input))

	for i := 0; i < len(input); i++ {
		c := input[i]
		// Check if character is in safeChars
		for j := 0; j < len(safeChars); j++ {
			if c == safeChars[j] {
				result = append(result, c)
				break
			}
		}
	}

	return string(result)
}

// EncodeBytesAbove7F URL-encodes bytes with value > 0x7F.
// Ported from: Utilities.java encodeBytesAbove7F() (lines 1146-1164)
//
// Algorithm:
//  1. Loop through input bytes
//  2. If byte > 0x7F, encode as %XX
//  3. Otherwise keep as-is
//
// Parameters:
//   - input: String that may contain high bytes
//
// Returns:
//   - String with high bytes URL-encoded
//
// Example:
//
//	encoded := EncodeBytesAbove7F("hello\x80world")
//	// Returns "hello%80world"
func EncodeBytesAbove7F(input string) string {
	if input == "" {
		return ""
	}

	// Hex characters for encoding
	hexChars := []byte("0123456789ABCDEF")

	// Count bytes > 0x7F to calculate result size
	highByteCount := 0
	for i := 0; i < len(input); i++ {
		if input[i] > 0x7F {
			highByteCount++
		}
	}

	if highByteCount == 0 {
		return input
	}

	// Each high byte expands from 1 to 3 characters (%XX)
	result := make([]byte, 0, len(input)+highByteCount*2)

	for i := 0; i < len(input); i++ {
		b := input[i]
		if b > 0x7F {
			// Encode as %XX
			result = append(result, '%')
			result = append(result, hexChars[b>>4])
			result = append(result, hexChars[b&0x0F])
		} else {
			result = append(result, b)
		}
	}

	return string(result)
}

// ==================== INTERNAL FUNCTIONS ====================

// Random number generator state for internal use
var (
	randomMu   sync.Mutex
	randomSeed int64
)

func init() {
	randomSeed = time.Now().UnixNano()
}

// nextRandom generates a pseudo-random number using LCG algorithm.
// Simple linear congruential generator for internal use.
func nextRandom() int64 {
	randomMu.Lock()
	defer randomMu.Unlock()

	// LCG parameters (same as java.util.Random)
	randomSeed = (randomSeed*0x5DEECE66D + 0xB) & ((1 << 48) - 1)
	return randomSeed >> 17
}

// randomString generates a random alphanumeric string (internal helper).
// Ported from: Utilities.java randomString() (lines 251-262)
//
// Algorithm:
//  1. Define charset (alphanumeric)
//  2. Generate random index for each position
//  3. Build string from selected characters
//
// Parameters:
//   - length: Desired string length
//
// Returns:
//   - Random alphanumeric string
//
// Example:
//
//	s := randomString(8)  // e.g., "a7Bx9kPm"
func randomString(length int) string {
	if length <= 0 {
		return ""
	}

	// Alphanumeric charset
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetLen := int64(len(charset))

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		idx := nextRandom() % charsetLen
		if idx < 0 {
			idx = -idx
		}
		result[i] = charset[idx]
	}

	return string(result)
}

// generateCanary generates a canary string for testing (internal).
// Ported from: Utilities.java generateCanary()
//
// Canary strings are used to detect reflection in responses.
// Format: "zxcv" + random(4) + "bnm" - easy to search, unlikely to appear naturally.
//
// Returns:
//   - Canary string (e.g., "zxcva7B9bnm")
//
// Example:
//
//	canary := generateCanary()  // "zxcvXy8Pbnm"
func generateCanary() string {
	return "zxcv" + randomString(4) + "bnm"
}

// mangle generates a deterministic random-looking string from seed (internal).
// Ported from: Utilities.java mangle() concept
//
// Creates a reproducible "random" string based on input seed.
// Useful for generating unique but predictable markers.
//
// Algorithm:
//  1. Use seed characters as basis
//  2. Apply simple transformation to each character
//  3. Ensure output is alphanumeric
//
// Parameters:
//   - seed: Input seed string
//
// Returns:
//   - Mangled string
//
// Example:
//
//	m := mangle("test")  // Same seed always produces same output
func mangle(seed string) string {
	if seed == "" {
		return ""
	}

	// Alphanumeric charset for output
	charset := "abcdefghijklmnopqrstuvwxyz0123456789"
	charsetLen := len(charset)

	result := make([]byte, len(seed))

	// Simple deterministic transformation
	acc := int64(0)
	for i := 0; i < len(seed); i++ {
		// Accumulate character values with position
		acc = (acc*31 + int64(seed[i])) % int64(charsetLen*1000)
		idx := int(acc) % charsetLen
		if idx < 0 {
			idx = -idx
		}
		result[i] = charset[idx]
	}

	return string(result)
}
