package utils

import (
	"unicode/utf16"
	// "bytes" // Not strictly needed for this direct port's string conversion
)

// --- Public Static Methods ---

// We will implement that signature and make it call the more general version.
func BytesToString(data []byte) string {
	if data == nil {
		return ""
	}
	return BytesToStringInRange(data, 0, len(data))
}

// This is the core logic for byte array to string conversion.
func BytesToStringInRange(data []byte, startIndex int, endIndex int) string {
	if data == nil {
		return ""
	}

	if startIndex < 0 || startIndex > len(data) || endIndex < 0 || startIndex+endIndex > len(data) {
		// Handle invalid range, perhaps return empty string or panic depending on desired strictness
		return ""
	}

	sourceBytes := data[startIndex : startIndex+endIndex]

	// This creates a pseudo UTF-16BE byte array where high bytes are 0.

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
