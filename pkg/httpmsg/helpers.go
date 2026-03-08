package httpmsg

import "errors"

// helpers.go - Helper utilities ported from Burp Suite
// Ported from: burp/d4n.java IExtensionHelpers methods (lines 235-282)
//              net/portswigger/ls.java helper methods

// IndexOf finds the first occurrence of a pattern in data.
// Ported from: d4n.java indexOf() method (lines 265-282)
//
//	net/portswigger/ls.java a() method (lines 179-181)
//
// Algorithm (from ls.java lines 179-181):
// 1. Validate inputs (null checks, bounds checks)
// 2. Call ls.a(data, pattern, caseSensitive, from, to) which uses loop-based search
// 3. Return position or -1 if not found
//
// The actual search is performed by ls.java method a() which:
// - Uses a Boyer-Moore-like optimization with caching (m1 class)
// - For case-insensitive, converts bytes to lowercase during comparison
// - Returns first match position or -1
//
// Example:
//
//	data := []byte("Hello World")
//	pos := IndexOf(data, []byte("World"), true, 0, len(data))
//	// Returns 6
//
//	pos := IndexOf(data, []byte("world"), false, 0, len(data))
//	// Returns 6 (case-insensitive)
//
// Parameters:
//   - haystack: Data to search in (cannot be null)
//   - needle: Pattern to find (cannot be null)
//   - caseSensitive: Whether search is case-sensitive
//   - start: Start position (must be >= 0)
//   - end: End position (must be >= start and <= len(haystack))
//
// Returns:
//   - Position of first match, or -1 if not found
//   - Returns -1 if inputs are invalid
func IndexOf(haystack, needle []byte, caseSensitive bool, start, end int) int {
	// Input validation (d4n.java lines 267-276)
	if haystack == nil {
		return -1
	}
	if needle == nil {
		return -1
	}
	if start < 0 {
		return -1
	}
	if end < start || end > len(haystack) {
		return -1
	}

	needleLen := len(needle)
	if needleLen == 0 {
		return start
	}

	// Cannot find pattern if search range is too small
	if end-start < needleLen {
		return -1
	}

	// Loop-based search (from ls.java a() method concept)
	// We use a simple loop implementation instead of Boyer-Moore
	// to keep it straightforward and match Burp's behavior
	for i := start; i <= end-needleLen; i++ {
		matched := true

		// Check if pattern matches at position i
		for j := 0; j < needleLen; j++ {
			haystackByte := haystack[i+j]
			needleByte := needle[j]

			// Case-insensitive comparison if needed
			if !caseSensitive {
				haystackByte = ToLowerByte(haystackByte)
				needleByte = ToLowerByte(needleByte)
			}

			if haystackByte != needleByte {
				matched = false
				break
			}
		}

		if matched {
			return i
		}
	}

	return -1
}

// GetRequestParameter finds a parameter by name in a request.
// Ported from: d4n.java getRequestParameter() method (lines 23-48)
//
// Algorithm (from d4n.java lines 23-48):
// 1. Validate inputs: request and name cannot be null (lines 27-30)
// 2. Analyze request to extract all parameters (line 32)
//   - g7t.a(null, var1, (byte)2, this.a).c returns list of parameters
//
// 3. Loop through parameters to find matching name (lines 32-40)
//   - var2.equals(var5.be()) checks if names match
//
// 4. Return first match or null (lines 34, 42)
//
// Example:
//
//	request := []byte("GET /api?id=123&name=test HTTP/1.1\r\n\r\n")
//	param, _ := GetRequestParameter(request, "id")
//	// param.Name = "id", param.Value = "123"
//
//	param, _ := GetRequestParameter(request, "missing")
//	// param = nil
//
// Parameters:
//   - request: HTTP request bytes (cannot be null)
//   - name: Parameter name to find (cannot be null)
//
// Returns:
//   - Param object or nil if not found
//   - Error if request is malformed or inputs are null
func GetRequestParameter(request []byte, name string) (*Param, error) {
	// Input validation (d4n.java lines 27-30)
	if request == nil {
		return nil, errors.New("request cannot be null")
	}
	if name == "" {
		return nil, errors.New("parameter name cannot be null")
	}

	// Analyze request to extract all parameters (d4n.java line 32)
	// g7t.a() is the request analyzer that returns RequestInfo
	info, err := AnalyzeRequest(request)
	if err != nil {
		return nil, err
	}

	// Loop through parameters to find matching name (d4n.java lines 32-40)
	for _, param := range info.Parameters {
		// d4n.java line 33: var2.equals(var5.be())
		// be() returns parameter name
		if name == param.Name() {
			return param, nil
		}
	}

	// Not found (d4n.java line 42)
	return nil, nil
}

// ByteArrayEquals compares two byte arrays for equality.
// Ported from: net/portswigger/ls.java d() method (lines 10-34)
//
// Algorithm (from ls.java lines 10-34):
// 1. Check if both arrays are null (line 12)
// 2. Check if lengths differ (lines 13-15)
// 3. Loop through arrays comparing each byte (lines 16-27)
// 4. Return true if all bytes match, false otherwise
//
// Example:
//
//	a := []byte("hello")
//	b := []byte("hello")
//	c := []byte("world")
//	ByteArrayEquals(a, b) // true
//	ByteArrayEquals(a, c) // false
//
// Parameters:
//   - a: First byte array
//   - b: Second byte array
//
// Returns:
//   - true if arrays are equal, false otherwise
func ByteArrayEquals(a, b []byte) bool {
	// Null checks (ls.java line 12)
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Length check (ls.java lines 13-15)
	if len(a) != len(b) {
		return false
	}

	// Byte-by-byte comparison (ls.java lines 16-27)
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// ByteArrayEqualsCaseInsensitive compares two byte arrays (case-insensitive).
// Based on ls.java comparison logic with case-insensitive flag.
//
// Algorithm:
// 1. Check if both arrays are null
// 2. Check if lengths differ
// 3. Loop through arrays comparing each byte (lowercased)
// 4. Return true if all bytes match, false otherwise
//
// Example:
//
//	a := []byte("Hello")
//	b := []byte("HELLO")
//	c := []byte("world")
//	ByteArrayEqualsCaseInsensitive(a, b) // true
//	ByteArrayEqualsCaseInsensitive(a, c) // false
//
// Parameters:
//   - a: First byte array
//   - b: Second byte array
//
// Returns:
//   - true if arrays are equal (ignoring case), false otherwise
func ByteArrayEqualsCaseInsensitive(a, b []byte) bool {
	// Null checks
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Length check
	if len(a) != len(b) {
		return false
	}

	// Byte-by-byte comparison with lowercase conversion
	for i := 0; i < len(a); i++ {
		if ToLowerByte(a[i]) != ToLowerByte(b[i]) {
			return false
		}
	}

	return true
}

// ToLowerByte converts a single byte to lowercase if it's an ASCII letter.
// Ported from: net/portswigger/ls.java a(byte) method (lines 367-373)
//
// Algorithm (from ls.java lines 367-373):
// 1. Check if byte is uppercase letter (A-Z, 65-90)
//   - if (var0 < 91 && var0 > 64)
//
// 2. If yes, add 32 to convert to lowercase
//   - var0 = (byte)(var0 + 32)
//
// 3. Return byte
//
// Example:
//
//	ToLowerByte('A') // returns 'a'
//	ToLowerByte('z') // returns 'z'
//	ToLowerByte('1') // returns '1'
//
// Parameters:
//   - b: Byte to convert
//
// Returns:
//   - Lowercase byte if input is uppercase letter, otherwise unchanged
func ToLowerByte(b byte) byte {
	// Check if uppercase letter (ls.java line 368)
	// A-Z is 65-90 (< 91 && > 64)
	if b < 91 && b > 64 {
		// Convert to lowercase by adding 32 (ls.java line 369)
		return b + 32
	}
	return b
}

// ByteArrayStartsWith checks if haystack starts with needle at given offset.
// Ported from: net/portswigger/ls.java a() method (lines 331-352)
//
// Algorithm (from ls.java lines 331-352):
// 1. Validate inputs (lines 333)
// 2. Check if needle fits in remaining space (line 333)
// 3. Loop through needle comparing bytes at offset (lines 335-346)
// 4. Support case-insensitive mode (line 337)
//
// Example:
//
//	data := []byte("Hello World")
//	ByteArrayStartsWith(data, []byte("Hello"), true, 0)  // true
//	ByteArrayStartsWith(data, []byte("World"), true, 6)  // true
//	ByteArrayStartsWith(data, []byte("world"), false, 6) // true (case-insensitive)
//
// Parameters:
//   - haystack: Data to search in
//   - needle: Pattern to match
//   - caseSensitive: Whether comparison is case-sensitive
//   - offset: Position in haystack to start comparison
//
// Returns:
//   - true if haystack starts with needle at offset
func ByteArrayStartsWith(haystack, needle []byte, caseSensitive bool, offset int) bool {
	// Input validation (ls.java line 333)
	if haystack == nil || needle == nil {
		return false
	}

	// Check if needle fits (ls.java line 333)
	if len(needle) > len(haystack)-offset {
		return false
	}

	// Loop through needle comparing bytes (ls.java lines 335-346)
	for i := 0; i < len(needle); i++ {
		haystackByte := haystack[i+offset]
		needleByte := needle[i]

		// Case-insensitive comparison if needed (ls.java line 337)
		if !caseSensitive {
			haystackByte = ToLowerByte(haystackByte)
		}

		if haystackByte != needleByte {
			return false
		}
	}

	return true
}

// IndexOfByteInRange finds a byte within a range.
// Ported from: net/portswigger/ls.java a(byte[], byte, boolean, int, int) method (lines 229-254)
//
// Algorithm (from ls.java lines 229-254):
// 1. Validate input (line 232)
// 2. Convert target byte to lowercase if case-insensitive (lines 234-236)
// 3. Loop through range (lines 238-250)
// 4. Compare bytes (optionally lowercasing haystack byte) (line 242)
// 5. Return index if found, -1 otherwise
//
// Example:
//
//	data := []byte("Hello World")
//	IndexOfByteInRange(data, 'W', true, 0, len(data))  // 6
//	IndexOfByteInRange(data, 'w', false, 0, len(data)) // 6 (case-insensitive)
//
// Parameters:
//   - haystack: Data to search in
//   - target: Byte to find
//   - caseSensitive: Whether search is case-sensitive
//   - start: Start position
//   - end: End position
//
// Returns:
//   - Index of first match, or -1 if not found
func IndexOfByteInRange(haystack []byte, target byte, caseSensitive bool, start, end int) int {
	// Input validation (ls.java line 232)
	if haystack == nil {
		return -1
	}

	// Convert target to lowercase if case-insensitive (ls.java lines 234-236)
	if !caseSensitive {
		target = ToLowerByte(target)
	}

	// Bounds checking
	if end > len(haystack) {
		end = len(haystack)
	}

	// Loop through range (ls.java lines 238-250)
	for i := start; i < end; i++ {
		haystackByte := haystack[i]

		// Apply case transformation if needed (ls.java line 242)
		if !caseSensitive {
			haystackByte = ToLowerByte(haystackByte)
		}

		if haystackByte == target {
			return i
		}
	}

	return -1
}
