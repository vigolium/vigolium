package utils

import (
	"bytes"
	// "unicode" // For more robust case conversion if needed, but sticking to direct byte manipulation
)

// --- Public Static Methods (Exported) ---

// NetPortswiggerNkE converts all uppercase ASCII characters in a byte slice to lowercase, in-place.
// Corresponds to public static void e(byte[] var0) in nk.java
func NetPortswiggerNkE(data []byte) {
	netPortswiggerNkAToLower(data, 0)
}

// netPortswiggerNkAToLower is the internal helper for converting to lowercase from a starting index.
// Corresponds to private static void a(byte[] var0, int var1) in nk.java
func netPortswiggerNkAToLower(data []byte, startIndex int) {
	if data == nil {
		return
	}
	for i := startIndex; i < len(data); i++ {
		if data[i] >= 'A' && data[i] <= 'Z' { // ASCII 'A' to 'Z'
			data[i] = data[i] + 32 // Convert to lowercase
		}
	}
}

// NetPortswiggerNkD converts all lowercase ASCII characters in a byte slice to uppercase, in-place.
// Corresponds to public static void d(byte[] var0) in nk.java
// The ls.b() logic is ignored as it seems to be for external flow control/debug.
func NetPortswiggerNkD(data []byte) {
	if data == nil {
		return
	}
	for i := 0; i < len(data); i++ {
		if data[i] >= 'a' && data[i] <= 'z' { // ASCII 'a' to 'z'
			data[i] = data[i] - 32 // Convert to uppercase
		}
	}
}

// NetPortswiggerNkC converts the first ASCII character of a byte slice to uppercase
// and the rest to lowercase, in-place (Title Case like).
// Corresponds to public static void c(byte[] var0) in nk.java
func NetPortswiggerNkC(data []byte) {
	if len(data) == 0 {
		return
	}
	if data[0] >= 'a' && data[0] <= 'z' { // First char to uppercase
		data[0] = data[0] - 32
	}
	netPortswiggerNkAToLower(data, 1) // Rest to lowercase
}

// NetPortswiggerNkA converts the first ASCII character of a byte slice to uppercase, in-place.
// Other characters are not changed.
// Corresponds to public static void a(byte[] var0) in nk.java
func NetPortswiggerNkAFirstCharUpper(data []byte) { // Renamed to avoid conflict
	if len(data) == 0 {
		return
	}
	if data[0] >= 'a' && data[0] <= 'z' { // First char to uppercase
		data[0] = data[0] - 32
	}
}

// NetPortswiggerNkASingleByteToLower converts a single ASCII byte to lowercase.
// Corresponds to public static byte a(byte var0) in nk.java
func NetPortswiggerNkASingleByteToLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// NetPortswiggerNkBTruncateOrGet is an alias for NetPortswiggerNkATruncateWithEllipsis with offset 0.
// Corresponds to public static byte[] b(byte[] var0, int var1, int var2) in nk.java
func NetPortswiggerNkBTruncateOrGet(
	data []byte,
	maxLengthBeforeTruncate int,
	newLengthForTruncatedPart int,
) []byte {
	return NetPortswiggerNkATruncateWithEllipsis(
		data,
		0,
		maxLengthBeforeTruncate,
		newLengthForTruncatedPart,
	)
}

// NetPortswiggerNkATruncateWithEllipsis truncates a byte slice if it's longer than a threshold,
// appending " ..." to the truncated part.
// Corresponds to public static byte[] a(byte[] var0, int var1, int var2, int var3) in nk.java
func NetPortswiggerNkATruncateWithEllipsis(
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
		// Equivalent to a(var0, var1, var0.length) which is a slice from offset to end
		// Ensure offset and length for slicing are valid
		if offset > len(data) { // Should be caught by earlier check, but for safety
			return []byte{} // return empty if offset is out of bounds for slicing
		}
		return NetPortswiggerNkACopyOfRange(data, offset, len(data)) // Use the copyOfRange logic
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

// NetPortswiggerNkCombine concatenates multiple byte slices into one.
// Corresponds to public static byte[] a(byte[]... var0) in nk.java
// This was previously stubbed as NetPortswiggerNkCombine in stubs.go and used by hnx.go
func NetPortswiggerNkCombine(slices ...[]byte) []byte {
	// The ls.b() and agd.i() calls related to loop control are ignored.
	var buf bytes.Buffer
	for _, s := range slices {
		if s != nil { // Java varargs can contain null arrays
			buf.Write(s)
		}
	}
	return buf.Bytes()
}

// NetPortswiggerNkACopyOfRange creates a copy of a range within a byte slice.
// Corresponds to public static byte[] a(byte[] var0, int var1, int var2) in nk.java
func NetPortswiggerNkACopyOfRange(data []byte, start int, end int) []byte {
	// The ls.b() and agd.d() calls are ignored.
	if data == nil {
		return nil
	}
	// Basic bounds checking for Java-like behavior (NullPointerException or IndexOutOfBounds)
	if start < 0 || end < start || end > len(data) {
		// Depending on strictness, could panic or return nil/empty.
		// Java's System.arraycopy would throw IndexOutOfBoundsException.
		// Returning nil to indicate error for now.
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

// NetPortswiggerNkBCopyOf creates a full copy of a byte slice.
// Corresponds to public static byte[] b(byte[] var0) in nk.java
func NetPortswiggerNkBCopyOf(data []byte) []byte {
	if data == nil {
		return nil
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result
}
