package utils

import (
	"bytes"
	// "unicode" // For more robust case conversion if needed, but sticking to direct byte manipulation
)

// --- Public Static Methods (Exported) ---

// ToLowerASCII converts all uppercase ASCII characters in a byte slice to lowercase, in-place.
func ToLowerASCII(data []byte) {
	toLowerASCIIFrom(data, 0)
}

// toLowerASCIIFrom is the internal helper for converting to lowercase from a starting index.
func toLowerASCIIFrom(data []byte, startIndex int) {
	if data == nil {
		return
	}
	for i := startIndex; i < len(data); i++ {
		if data[i] >= 'A' && data[i] <= 'Z' { // ASCII 'A' to 'Z'
			data[i] = data[i] + 32 // Convert to lowercase
		}
	}
}

// ToUpperASCII converts all lowercase ASCII characters in a byte slice to uppercase, in-place.
func ToUpperASCII(data []byte) {
	if data == nil {
		return
	}
	for i := 0; i < len(data); i++ {
		if data[i] >= 'a' && data[i] <= 'z' { // ASCII 'a' to 'z'
			data[i] = data[i] - 32 // Convert to uppercase
		}
	}
}

// CapitalizeFirst converts the first ASCII character of a byte slice to uppercase
// and the rest to lowercase, in-place (title case).
func CapitalizeFirst(data []byte) {
	if len(data) == 0 {
		return
	}
	if data[0] >= 'a' && data[0] <= 'z' { // First char to uppercase
		data[0] = data[0] - 32
	}
	toLowerASCIIFrom(data, 1) // Rest to lowercase
}

// UpperFirst converts the first ASCII character of a byte slice to uppercase, in-place.
// Other characters are not changed.
func UpperFirst(data []byte) {
	if len(data) == 0 {
		return
	}
	if data[0] >= 'a' && data[0] <= 'z' { // First char to uppercase
		data[0] = data[0] - 32
	}
}

// SingleByteToLower converts a single ASCII byte to lowercase.
func SingleByteToLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// TruncateOrGet is an alias for TruncateWithEllipsis with offset 0.
func TruncateOrGet(
	data []byte,
	maxLengthBeforeTruncate int,
	newLengthForTruncatedPart int,
) []byte {
	return TruncateWithEllipsis(
		data,
		0,
		maxLengthBeforeTruncate,
		newLengthForTruncatedPart,
	)
}

// TruncateWithEllipsis truncates a byte slice if it's longer than a threshold,
// appending " ..." to the truncated part.
func TruncateWithEllipsis(
	data []byte,
	offset int,
	maxLengthBeforeTruncate int,
	newLengthForTruncatedPart int,
) []byte {
	if data == nil {
		return nil
	}

	// Basic bounds checking for offset to prevent panic on initial slice check
	if offset < 0 || offset > len(data) {
		return nil // Or handle error appropriately
	}

	if len(data)-offset <= maxLengthBeforeTruncate {
		if offset == 0 {
			return data
		}
		if offset > len(data) {
			return []byte{}
		}
		return CopyOfRange(data, offset, len(data))
	}

	// Ensure newLengthForTruncatedPart is not negative and not excessively large for the source
	if newLengthForTruncatedPart < 0 {
		newLengthForTruncatedPart = 0
	}
	availableCharsForTrunc := len(data) - offset
	if newLengthForTruncatedPart > availableCharsForTrunc {
		newLengthForTruncatedPart = availableCharsForTrunc
	}

	// byte[] var4 = new byte[var3 + 4]; // var3 is newLengthForTruncatedPart
	result := make([]byte, newLengthForTruncatedPart+4)
	copy(result, data[offset:offset+newLengthForTruncatedPart])
	result[newLengthForTruncatedPart] = ' '
	result[newLengthForTruncatedPart+1] = '.'
	result[newLengthForTruncatedPart+2] = '.'
	result[newLengthForTruncatedPart+3] = '.'
	return result
}

// CombineByteSlices concatenates multiple byte slices into one.
func CombineByteSlices(slices ...[]byte) []byte {
	var buf bytes.Buffer
	for _, s := range slices {
		if s != nil {
			buf.Write(s)
		}
	}
	return buf.Bytes()
}

// CopyOfRange creates a copy of a range within a byte slice.
func CopyOfRange(data []byte, start int, end int) []byte {
	if data == nil {
		return nil
	}
	if start < 0 || end < start || end > len(data) {
		return nil
	}

	length := end - start
	if length == 0 {
		return []byte{}
	}

	result := make([]byte, length)
	copy(result, data[start:end])
	return result
}

// CopyBytes creates a full copy of a byte slice.
func CopyBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result
}
