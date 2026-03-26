package httpmsg

import "errors"

// helpers.go - Helper utilities for HTTP message processing

// IndexOf finds the first occurrence of a pattern in data.
// Uses loop-based search with optional case-insensitive comparison.
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
	// Input validation
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

	// Loop-based search
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
	// Input validation
	if request == nil {
		return nil, errors.New("request cannot be null")
	}
	if name == "" {
		return nil, errors.New("parameter name cannot be null")
	}

	// Analyze request to extract all parameters
	info, err := AnalyzeRequest(request)
	if err != nil {
		return nil, err
	}

	// Loop through parameters to find matching name
	for _, param := range info.Parameters {
		if name == param.Name() {
			return param, nil
		}
	}

	// Not found
	return nil, nil
}

// ByteArrayEquals compares two byte arrays for equality.
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

	// Byte-by-byte comparison
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// ByteArrayEqualsCaseInsensitive compares two byte arrays (case-insensitive).
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
	// A-Z is 65-90
	if b < 91 && b > 64 {
		return b + 32
	}
	return b
}

// ByteArrayStartsWith checks if haystack starts with needle at given offset.
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
	if haystack == nil || needle == nil {
		return false
	}

	if len(needle) > len(haystack)-offset {
		return false
	}

	for i := 0; i < len(needle); i++ {
		haystackByte := haystack[i+offset]
		needleByte := needle[i]

		// Case-insensitive comparison if needed
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
	if haystack == nil {
		return -1
	}

	// Convert target to lowercase if case-insensitive
	if !caseSensitive {
		target = ToLowerByte(target)
	}

	// Bounds checking
	if end > len(haystack) {
		end = len(haystack)
	}

	// Loop through range
	for i := start; i < end; i++ {
		haystackByte := haystack[i]

		// Apply case transformation if needed
		if !caseSensitive {
			haystackByte = ToLowerByte(haystackByte)
		}

		if haystackByte == target {
			return i
		}
	}

	return -1
}
