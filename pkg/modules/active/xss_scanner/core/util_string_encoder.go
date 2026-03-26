package core

import (
	"fmt"
	"strings"
	"unicode"
)

// 1. Encodes the string 's' using c6wEncodeStringInternal (if mode is odd).
// 2. Prepends a NUL character to 's' (if mode is even and its second bit is set).
// 3. Returns 's' as is (if mode is even and its second bit is not set).
func EncodeStringWithMode(inputString string, encodingMode int) string {
	if (encodingMode & 1) == 1 { // If mode's LSB is 1 (i.e., mode is odd)
		return customPercentEncodeString(inputString)
	} else { // Mode is even
		if (encodingMode & 2) == 2 { // If mode's second LSB is 1 (e.g., mode 2, 6, 10)
			return "\x00" + inputString // Prepend NUL character
		}
		return inputString // Return s as is (e.g., mode 0, 4, 8)
	}
}

// This function performs a custom URL-like encoding.
// Alphanumeric characters are appended directly.
// Other characters are percent-encoded:
// - '%' is prepended.
// - The character's Unicode value is converted to a lowercase hex string.
// - If hex string is 1 char long (e.g., "a"), "0" is prepended (e.g., "%0a").
// - If hex string is 2 chars long (e.g., "20"), it's appended (e.g., "%20").
// - If hex string is >2 chars long (for chars > 0xFF), its last two hex digits are appended (e.g., for ǿ (hex "1ff"), "%ff" is appended).
func customPercentEncodeString(s string) string {
	var encodedBuilder strings.Builder

	for _, char := range s {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			encodedBuilder.WriteRune(char)
		} else {
			encodedBuilder.WriteString("%")
			hexValueString := fmt.Sprintf("%x", char)

			if len(hexValueString) == 1 { // e.g., for char value 7, hexStr is "7"
				encodedBuilder.WriteString("0")
				encodedBuilder.WriteString(hexValueString) // -> %07
			} else if len(hexValueString) == 2 { // e.g., for char value 32, hexStr is "20"
				encodedBuilder.WriteString(hexValueString) // -> %20
			} else { // For char values > 255, hexStr length > 2
				// e.g., for char ǿ (value 511), hexStr is "1ff". Appends "ff". -> %ff
				// e.g., for char ሴ (value 4660), hexStr is "1234". Appends "34". -> %34
				encodedBuilder.WriteString(hexValueString[len(hexValueString)-2:])
			}
		}
	}
	return encodedBuilder.String()
}
