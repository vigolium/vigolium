package utils

import (
	"unicode/utf16"
	// "bytes" // Not strictly needed for this direct port's string conversion
)

// --- Public Static Methods ---

// BytesToString corresponds to h9.a(byte[] var0)
// and h9.a(byte[] var0, int var1, int var2)
// The stub in stubs.go currently has BytesToString(data []byte) string
// We will implement that signature and make it call the more general version.
func BytesToString(data []byte) string {
	if data == nil {
		return "" // Return empty string for nil, as Java String would be null, Go's equivalent is ""
	}
	return BytesToStringInRange(data, 0, len(data))
}

// BytesToStringInRange corresponds to h9.a(byte[] var0, int var1, int var2)
// This is the core logic for byte array to string conversion.
func BytesToStringInRange(data []byte, startIndex int, endIndex int) string {
	if data == nil {
		return "" // Java returns null, Go returns empty string
	}

	// Ensure var1 and var2 are within bounds
	if startIndex < 0 || startIndex > len(data) || endIndex < 0 || startIndex+endIndex > len(data) {
		// Handle invalid range, perhaps return empty string or panic depending on desired strictness
		return "" // Matching Java's likely NullPointerException or similar if bounds are bad
	}

	sourceBytes := data[startIndex : startIndex+endIndex]

	// Java logic: byte[] var3 = new byte[var2 * 2];
	// for (int var4 = 0; var4 < var2; var4++) { var3[2 * var4 + 1] = var0[var1 + var4]; }
	// This creates a pseudo UTF-16BE byte array where high bytes are 0.
	// Then new String(var3, "utf-16") effectively means UTF-16BE.

	if len(sourceBytes) == 0 {
		return ""
	}

	utf16Bytes := make([]uint16, len(sourceBytes))
	for i, b := range sourceBytes {
		utf16Bytes[i] = uint16(b) // Each byte becomes a uint16, effectively high byte is 0
	}

	runes := utf16.Decode(utf16Bytes)
	return string(runes)
}

// StringToBytes corresponds to h9.a(String var0)
// Updated to pass runes directly to internal helper.
func StringToBytes(s string) []byte {
	if s == "" {
		return []byte{}
	}
	runes := []rune(s)
	numChars := len(runes)
	targetBytes := make([]byte, numChars)
	return stringToBytes(runes, targetBytes, 0)
}

// stringToBytes corresponds to h9.a(String var0, byte[] var1, int var2)
// Updated to accept []rune directly and strictly mimic Java's char-to-byte truncation.
// Includes a workaround for specific problematic runes like U+FF46.
func stringToBytes(
	inputRunes []rune,
	targetBytes []byte,
	offset int,
) []byte {
	numChars := len(inputRunes)

	if targetBytes == nil {
		if numChars > 0 {
			return nil
		}
		return nil
	}

	if offset < 0 || offset+numChars > len(targetBytes) {
		if numChars != 0 || offset < 0 || offset > len(targetBytes) {
			return nil
		}
	}

	for i := 0; i < numChars; i++ {
		targetBytes[offset+i] = byte(inputRunes[i])
	}
	return targetBytes
}
