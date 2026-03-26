package httpmsg

// byte_utils.go - Byte array utilities for HTTP message parsing

const (
	// HTTP line ending bytes
	CR = byte(13) // \r (0x0D)
	LF = byte(10) // \n (0x0A)
)

// FindBodyOffset finds the offset where the HTTP body starts in a request or response.
// This is the position immediately after the header/body separator.
//
// Algorithm:
//  1. Search for CRLF CRLF sequence (0x0D 0x0A 0x0D 0x0A)
//  2. If not found, search for LF LF sequence (0x0A 0x0A)
//  3. If found, return offset AFTER the separator (body start position)
//  4. Handle edge case: check last 2 bytes for LF LF if main loop didn't find it
//  5. If no separator found, return length of data (no body)
//
// Example:
//
//	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY")
//	offset := FindBodyOffset(request)
//	// Returns 38 (position where "BODY" starts)
//
// Parameters:
//   - request: HTTP request or response bytes
//
// Returns:
//   - Offset where body starts (after the separator)
//   - If no separator found, returns len(request)
func FindBodyOffset(request []byte) int {
	if request == nil {
		return -1
	}

	length := len(request)
	offset := -1

	// Main loop: search for CRLF CRLF or LF LF
	for i := 0; i < length-3; i++ {
		// Check for CRLF CRLF (13 10 13 10)
		if request[i] == CR && request[i+1] == LF &&
			request[i+2] == CR && request[i+3] == LF {
			offset = i + 4
			break
		}

		// Check for LF LF (10 10)
		if request[i] == LF && request[i+1] == LF {
			offset = i + 2
			break
		}
	}

	// Edge case: check last 2 bytes for LF LF
	if offset == -1 && length >= 3 {
		for i := length - 3; i < length-1; i++ {
			if request[i] == LF && request[i+1] == LF {
				offset = i + 2
				break
			}
		}
	}

	// If no separator found, return length (no body)
	if offset == -1 {
		return length
	}

	return offset
}

// FindBodyEnd finds the offset where the HTTP body ends (before trailing separators).
// This searches backwards from the end to find trailing CRLF CRLF or LF LF sequences.
//
// Algorithm:
//  1. Search backwards for CRLF CRLF or LF LF
//  2. Return offset BEFORE the separator (end of actual body content)
//  3. If not found, return startOffset
//
// Example:
//
//	response := []byte("HTTP/1.1 200 OK\r\n\r\nBODY\r\n\r\n")
//	bodyStart := FindBodyOffset(response)  // Returns 19
//	bodyEnd := FindBodyEnd(response, bodyStart)  // Returns 23 (before trailing \r\n\r\n)
//
// Parameters:
//   - request: HTTP request or response bytes
//   - startOffset: Position to start searching from (typically body start)
//
// Returns:
//   - Offset where body ends (before trailing separator)
//   - If no trailing separator, returns len(request)
func FindBodyEnd(request []byte, startOffset int) int {
	if request == nil {
		return -1
	}

	length := len(request)
	offset := -1

	// Search backwards for trailing separators
	// Start from a position that allows checking both CRLF CRLF and LF LF
	startPos := length - 2 // Need at least 2 bytes for LF LF
	if startPos < startOffset {
		return length
	}

	// First check for CRLF CRLF (4 bytes)
	if length >= 4 {
		for i := length - 4; i >= startOffset; i-- {
			if i+3 < length &&
				request[i] == CR && request[i+1] == LF &&
				request[i+2] == CR && request[i+3] == LF {
				offset = i
				break
			}
		}
	}

	// If no CRLF CRLF found, check for LF LF (2 bytes)
	if offset == -1 && length >= 2 {
		for i := length - 2; i >= startOffset; i-- {
			if i+1 < length &&
				request[i] == LF && request[i+1] == LF {
				offset = i
				break
			}
		}
	}

	if offset == -1 {
		return length
	}

	return offset
}

// SliceBytes performs safe byte slicing with bounds checking.
//
// Example:
//
//	data := []byte("hello world")
//	slice := SliceBytes(data, 0, 5)  // Returns []byte("hello")
//	slice := SliceBytes(data, 6, 20) // Returns []byte("world") - capped at length
//
// Parameters:
//   - data: Source byte array
//   - start: Start index (inclusive)
//   - end: End index (exclusive)
//
// Returns:
//   - Sliced byte array
//   - Empty slice if start >= len(data)
//   - Capped at len(data) if end > len(data)
func SliceBytes(data []byte, start, end int) []byte {
	if data == nil {
		return nil
	}

	length := len(data)

	// Bounds checking
	if start < 0 {
		start = 0
	}
	if start >= length {
		return []byte{}
	}
	if end < start {
		return []byte{}
	}
	if end > length {
		end = length
	}

	// Return the subslice
	return data[start:end]
}

// IndexOfByte finds the first occurrence of a target byte starting from startOffset.
//
// Algorithm:
//  1. Loop from startOffset to end of array
//  2. Compare each byte with target
//  3. Return index of first match
//  4. Return -1 if not found
//
// Example:
//
//	data := []byte("hello")
//	idx := IndexOfByte(data, 'l', 0)  // Returns 2 (first 'l')
//	idx := IndexOfByte(data, 'l', 3)  // Returns 3 (second 'l')
//	idx := IndexOfByte(data, 'x', 0)  // Returns -1 (not found)
//
// Parameters:
//   - data: Byte array to search in
//   - target: Byte to find
//   - startOffset: Position to start searching from
//
// Returns:
//   - Index of first occurrence, or -1 if not found
func IndexOfByte(data []byte, target byte, startOffset int) int {
	if data == nil {
		return -1
	}

	length := len(data)
	if startOffset < 0 {
		startOffset = 0
	}

	// Loop-based byte-by-byte search (NO REGEX per requirements)
	for i := startOffset; i < length; i++ {
		if data[i] == target {
			return i
		}
	}

	return -1
}

// IndexOfBytes finds the first occurrence of a target byte sequence starting from startOffset.
//
// Algorithm:
//  1. Loop from startOffset to end
//  2. For each position, check if target sequence matches
//  3. Use nested loop for multi-byte matching
//  4. Return index of first match
//  5. Return -1 if not found
//
// Example:
//
//	data := []byte("hello world")
//	idx := IndexOfBytes(data, []byte("wor"), 0)  // Returns 6
//	idx := IndexOfBytes(data, []byte("xyz"), 0)  // Returns -1
//
// Parameters:
//   - data: Byte array to search in
//   - target: Byte sequence to find
//   - startOffset: Position to start searching from
//
// Returns:
//   - Index of first occurrence, or -1 if not found
func IndexOfBytes(data []byte, target []byte, startOffset int) int {
	if data == nil || target == nil {
		return -1
	}

	dataLen := len(data)
	targetLen := len(target)

	if targetLen == 0 {
		return startOffset
	}
	if startOffset < 0 {
		startOffset = 0
	}
	if startOffset+targetLen > dataLen {
		return -1
	}

	// Loop-based byte-by-byte comparison
	for i := startOffset; i <= dataLen-targetLen; i++ {
		// Check if target sequence matches at position i
		matched := true
		for j := 0; j < targetLen; j++ {
			if data[i+j] != target[j] {
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

// IsHTTP2 checks if request uses HTTP/2 protocol.
//
// Algorithm:
//  1. Find end of first line
//  2. Check if line ends with "HTTP/2" or starts with pseudo-headers
//  3. Return true if HTTP/2 indicators found
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - true if request uses HTTP/2 protocol
//
// Example:
//
//	isH2 := IsHTTP2(request)  // "GET / HTTP/2\r\n..." → true
func IsHTTP2(request []byte) bool {
	if len(request) < 6 {
		return false
	}

	// Find end of first line
	lineEnd := 0
	for i := 0; i < len(request); i++ {
		if request[i] == CR || request[i] == LF {
			lineEnd = i
			break
		}
	}

	if lineEnd == 0 {
		lineEnd = len(request)
	}

	// Check for HTTP/2 at end of request line
	// "GET / HTTP/2" - HTTP/2 is 6 chars
	if lineEnd >= 6 {
		suffix := request[lineEnd-6 : lineEnd]
		if (suffix[0] == 'H' || suffix[0] == 'h') &&
			(suffix[1] == 'T' || suffix[1] == 't') &&
			(suffix[2] == 'T' || suffix[2] == 't') &&
			(suffix[3] == 'P' || suffix[3] == 'p') &&
			suffix[4] == '/' &&
			suffix[5] == '2' {
			return true
		}
	}

	// Check for HTTP/2 pseudo-headers (start with :)
	// e.g., ":method", ":path", ":authority"
	if request[0] == ':' {
		return true
	}

	return false
}

// ConvertToHTTP1 converts HTTP/2 request to HTTP/1.1.
//
// Algorithm:
//  1. Find "HTTP/2" in request line
//  2. Replace with "HTTP/1.1"
//  3. Return modified request
//
// Parameters:
//   - request: HTTP request bytes (may be HTTP/2)
//
// Returns:
//   - Request converted to HTTP/1.1
//
// Example:
//
//	req := ConvertToHTTP1(request)  // "HTTP/2" → "HTTP/1.1"
func ConvertToHTTP1(request []byte) []byte {
	if request == nil {
		return nil
	}

	// Find end of first line (or end of request if no line ending)
	lineEnd := len(request)
	for i := 0; i < len(request); i++ {
		if request[i] == CR || request[i] == LF {
			lineEnd = i
			break
		}
	}

	// Find HTTP/2 in first line
	http2Pos := -1
	for i := 0; i <= lineEnd-6; i++ {
		if (request[i] == 'H' || request[i] == 'h') &&
			(request[i+1] == 'T' || request[i+1] == 't') &&
			(request[i+2] == 'T' || request[i+2] == 't') &&
			(request[i+3] == 'P' || request[i+3] == 'p') &&
			request[i+4] == '/' &&
			request[i+5] == '2' {
			http2Pos = i
			break
		}
	}

	if http2Pos == -1 {
		// Not HTTP/2, return unchanged
		return request
	}

	// Replace HTTP/2 with HTTP/1.1
	// HTTP/2 is 6 bytes, HTTP/1.1 is 8 bytes
	result := make([]byte, 0, len(request)+2)
	result = append(result, request[:http2Pos]...)
	result = append(result, []byte("HTTP/1.1")...)
	result = append(result, request[http2Pos+6:]...)

	return result
}

// GetHeaders extracts all headers as string (excluding request/status line).
//
// Algorithm:
//  1. Find end of first line (request/status line)
//  2. Find body offset
//  3. Extract headers between these positions
//
// Parameters:
//   - message: HTTP request or response bytes
//
// Returns:
//   - Headers as string (e.g., "Host: example.com\r\nAccept: */*\r\n")
//
// Example:
//
//	headers := GetHeaders(request)  // "Host: example.com\r\nAccept: */*\r\n"
func GetHeaders(message []byte) string {
	return string(GetHeadersBytes(message))
}

// GetHeadersBytes extracts all headers as bytes (excluding request/status line).
// Returns the raw header bytes between first line and body.
//
// Algorithm:
//  1. Find end of first line (request/status line)
//  2. Find body offset (header/body separator)
//  3. Extract bytes between these positions (excluding separator)
//
// Parameters:
//   - message: HTTP request or response bytes
//
// Returns:
//   - Header bytes (empty if no headers)
//
// Example:
//
//	headers := GetHeadersBytes(request)
func GetHeadersBytes(message []byte) []byte {
	if message == nil {
		return nil
	}

	length := len(message)

	// Find end of first line
	firstLineEnd := 0
	for i := 0; i < length; i++ {
		if message[i] == LF {
			firstLineEnd = i + 1
			break
		}
	}

	if firstLineEnd == 0 || firstLineEnd >= length {
		return []byte{}
	}

	// Find body offset
	bodyOffset := FindBodyOffset(message)

	// Headers are between first line end and body separator
	// The separator itself is part of the header section
	if bodyOffset <= firstLineEnd {
		return []byte{}
	}

	// Exclude the final CRLFCRLF or LFLF separator
	headerEnd := bodyOffset
	if headerEnd >= 4 && message[headerEnd-4] == CR && message[headerEnd-3] == LF &&
		message[headerEnd-2] == CR && message[headerEnd-1] == LF {
		headerEnd -= 2 // Keep one CRLF, remove separator CRLF
	} else if headerEnd >= 2 && message[headerEnd-2] == LF && message[headerEnd-1] == LF {
		headerEnd-- // Keep one LF, remove separator LF
	}

	return message[firstLineEnd:headerEnd]
}
