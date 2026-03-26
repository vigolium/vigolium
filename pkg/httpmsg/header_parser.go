package httpmsg

// header_parser.go - HTTP header parsing logic
//
// Uses loop-based character-by-character parsing (no regex).

// Byte constants for parsing
// Note: CR and LF are defined in byte_utils.go
const (
	COLON = 0x3A // Colon :
	SPACE = 0x20 // Space
	TAB   = 0x09 // Tab
	SEMI  = 0x3B // Semicolon ;
	EQ    = 0x3D // Equals =
)

// ExtractHeaders extracts HTTP headers from byte slice.
//
// Parameters:
//   - request: HTTP request/response bytes
//   - startOffset: Starting position to parse from
//   - endOffset: Ending position (typically body start or end of data)
//
// Returns:
//   - headers: List of header lines including request/status line
//   - headerOffsets: Byte offset where each header starts
//   - error: Any parsing error
//
// Logic:
//  1. Loop through bytes from startOffset to endOffset
//  2. Find CRLF (\r\n) line terminators
//  3. Extract line between terminators
//  4. Skip empty lines
//  5. Track offset of each non-empty line
//  6. Return headers and their offsets
//
// Example:
//
//	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
//	headers, offsets, _ := ExtractHeaders(request, 0, 36)
//	// headers = ["GET / HTTP/1.1", "Host: example.com"]
//	// offsets = [0, 16]
func ExtractHeaders(request []byte, startOffset, endOffset int) ([]string, []int, error) {
	if request == nil {
		return []string{}, []int{}, nil
	}

	// Bounds checking
	if endOffset > len(request) {
		endOffset = len(request)
	}

	headers := []string{}
	headerOffsets := []int{}

	// Main parsing loop
	lineStart := startOffset

	// Loop through data looking for CRLF terminators
	for pos := startOffset; pos < endOffset; pos++ {
		// Check for CRLF line terminator
		if request[pos] == CR && pos+1 < endOffset && request[pos+1] == LF {
			// Extract line from lineStart to pos
			line := string(request[lineStart:pos])

			// Skip empty lines
			if len(line) > 0 {
				headers = append(headers, line)
				// Track offset of this header
				headerOffsets = append(headerOffsets, lineStart)
			}

			// Move to start of next line (skip CRLF)
			lineStart = pos + 2
		}
	}

	// Handle final line if no terminator at end
	if lineStart < endOffset {
		line := string(request[lineStart:endOffset])
		if len(line) > 0 {
			headers = append(headers, line)
			headerOffsets = append(headerOffsets, lineStart)
		}
	}

	return headers, headerOffsets, nil
}

// FindLineEnd finds the position of the next line terminator.
// Helper function for header parsing.
//
// Parameters:
//   - data: Byte slice to search
//   - start: Starting position
//   - end: Ending position
//
// Returns:
//   - Position of CR or LF, or end if not found
//
// Logic:
//   - Loop through bytes looking for 0x0D (CR) or 0x0A (LF)
//   - Return position when found
//   - Return end if no terminator found
func FindLineEnd(data []byte, start, end int) int {
	for i := start; i < end; i++ {
		if data[i] == CR || data[i] == LF {
			return i
		}
	}
	return end
}

// SkipLineTerminator advances position past line ending.
// Helper function for header parsing.
//
// Parameters:
//   - data: Byte slice
//   - pos: Current position (at CR or LF)
//   - end: End boundary
//
// Returns:
//   - New position after line terminator
//
// Logic:
//   - If at CRLF (\r\n), skip 2 bytes
//   - If at LF (\n) alone, skip 1 byte
//   - If at CR (\r) alone, skip 1 byte
func SkipLineTerminator(data []byte, pos, end int) int {
	if pos >= end {
		return pos
	}

	// Check for CRLF (2 bytes)
	if data[pos] == CR {
		if pos+1 < end && data[pos+1] == LF {
			return pos + 2 // Skip CRLF
		}
		return pos + 1 // Skip CR alone
	}

	// Check for LF (1 byte)
	if data[pos] == LF {
		return pos + 1
	}

	return pos
}

// GetHeader retrieves header value by name (case-insensitive).
//
// Parameters:
//   - headers: List of header lines from ExtractHeaders
//   - name: Header name to search for (e.g., "Content-Type")
//
// Returns:
//   - Header value (trimmed), or empty string if not found
//
// Logic:
//  1. Loop through headers, skipping request/status line
//  2. Parse each header as "Name: Value"
//  3. Compare name case-insensitively
//  4. Return trimmed value
//
// Example:
//
//	headers := []string{"GET / HTTP/1.1", "Host: example.com", "Content-Type: text/html"}
//	value := Header(headers, "content-type")
//	// value = "text/html"
func Header(headers []string, name string) string {
	// Loop through headers, skipping request line (index 0)
	for i := 1; i < len(headers); i++ {
		header := headers[i]

		// Find colon separator
		colonIdx := FindColonIndex(header)
		if colonIdx == -1 {
			continue
		}

		// Extract header name and value
		headerName := header[0:colonIdx]
		headerValue := header[colonIdx+1:]

		// Case-insensitive comparison
		if EqualsCaseInsensitive(headerName, name) {
			// Return trimmed value
			return TrimSpace(headerValue)
		}
	}

	// Not found
	return ""
}

// FindColonIndex finds the first colon in a header line.
// Helper function for header parsing.
//
// Parameters:
//   - header: Header line (e.g., "Content-Type: text/html")
//
// Returns:
//   - Index of first colon, or -1 if not found
//
// Logic:
//   - Loop through string looking for ':' character
//   - Return index when found
//   - Return -1 if not found
func FindColonIndex(header string) int {
	for i := 0; i < len(header); i++ {
		if header[i] == COLON {
			return i
		}
	}
	return -1
}

// EqualsCaseInsensitive compares two strings case-insensitively.
// Loop-based implementation (NO regex or library functions).
//
// Parameters:
//   - a, b: Strings to compare
//
// Returns:
//   - true if equal (case-insensitive), false otherwise
//
// Logic:
//  1. Check length first (fast path)
//  2. Loop through each character
//  3. Convert to lowercase and compare
func EqualsCaseInsensitive(a, b string) bool {
	// Length check (fast path)
	if len(a) != len(b) {
		return false
	}

	// Character-by-character comparison
	for i := 0; i < len(a); i++ {
		if ToLower(a[i]) != ToLower(b[i]) {
			return false
		}
	}

	return true
}

// ToLower converts ASCII character to lowercase.
// Loop-based helper (no library functions).
//
// Parameters:
//   - c: Character byte
//
// Returns:
//   - Lowercase version if uppercase ASCII letter, otherwise unchanged
func ToLower(c byte) byte {
	// ASCII uppercase letters: 0x41-0x5A (A-Z)
	// ASCII lowercase letters: 0x61-0x7A (a-z)
	// Difference: 0x20 (32)
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// TrimSpace removes leading and trailing whitespace.
// Loop-based implementation (NO regex or strings.TrimSpace).
//
// Parameters:
//   - s: String to trim
//
// Returns:
//   - String with leading/trailing spaces and tabs removed
//
// Logic:
//  1. Find first non-whitespace character (from start)
//  2. Find last non-whitespace character (from end)
//  3. Return substring
func TrimSpace(s string) string {
	// Find first non-whitespace
	start := 0
	for start < len(s) && IsWhitespace(s[start]) {
		start++
	}

	// All whitespace case
	if start >= len(s) {
		return ""
	}

	// Find last non-whitespace
	end := len(s) - 1
	for end >= start && IsWhitespace(s[end]) {
		end--
	}

	return s[start : end+1]
}

// IsWhitespace checks if character is space or tab.
// Helper for TrimSpace.
//
// Parameters:
//   - c: Character byte
//
// Returns:
//   - true if space (0x20) or tab (0x09)
func IsWhitespace(c byte) bool {
	return c == SPACE || c == TAB
}

// ParseContentType extracts MIME type and boundary from Content-Type header.
// Handles multipart/form-data boundary parsing.
//
// Parameters:
//   - headers: List of header lines from ExtractHeaders
//
// Returns:
//   - contentType: MIME type (e.g., "multipart/form-data")
//   - boundary: Boundary string for multipart, or empty string
//
// Logic:
//  1. Get Content-Type header value
//  2. Parse MIME type (before semicolon)
//  3. Parse parameters (after semicolon)
//  4. Extract boundary parameter if present
//
// Example:
//
//	headers := []string{"POST / HTTP/1.1", "Content-Type: multipart/form-data; boundary=----WebKit"}
//	contentType, boundary := ParseContentType(headers)
//	// contentType = "multipart/form-data"
//	// boundary = "----WebKit"
func ParseContentType(headers []string) (contentType string, boundary string) {
	// Get Content-Type header
	headerValue := Header(headers, "Content-Type")
	if headerValue == "" {
		return "", ""
	}

	// Find semicolon separator (before parameters)
	semiIdx := FindCharIndex(headerValue, SEMI)

	// Extract MIME type
	if semiIdx == -1 {
		// No parameters, just MIME type
		contentType = TrimSpace(headerValue)
		return contentType, ""
	}

	contentType = TrimSpace(headerValue[0:semiIdx])

	// Parse parameters (after semicolon)
	params := headerValue[semiIdx+1:]

	// Extract boundary parameter
	// Format: "boundary=value" or "boundary=\"value\""
	boundary = ParseParameter(params, "boundary")

	return contentType, boundary
}

// FindCharIndex finds first occurrence of character in string.
// Loop-based helper (no strings.Index).
//
// Parameters:
//   - s: String to search
//   - c: Character byte to find
//
// Returns:
//   - Index of first occurrence, or -1 if not found
func FindCharIndex(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ParseParameter extracts parameter value from header parameter string.
// Loop-based parsing for "name=value" or "name=\"value\"" format.
//
// Parameters:
//   - params: Parameter string (e.g., "boundary=----WebKit; charset=utf-8")
//   - name: Parameter name to extract
//
// Returns:
//   - Parameter value, or empty string if not found
//
// Logic:
//  1. Find parameter name (case-insensitive)
//  2. Skip past "name="
//  3. Handle quoted values ("value")
//  4. Handle unquoted values (until semicolon or end)
//
// Example:
//
//	params := "boundary=----WebKit; charset=utf-8"
//	value := ParseParameter(params, "boundary")
//	// value = "----WebKit"
func ParseParameter(params string, name string) string {
	params = TrimSpace(params)

	// Loop through parameter string looking for name
	pos := 0
	for pos < len(params) {
		// Skip leading whitespace
		for pos < len(params) && IsWhitespace(params[pos]) {
			pos++
		}

		// Find equals sign
		equalsIdx := pos
		for equalsIdx < len(params) && params[equalsIdx] != EQ && params[equalsIdx] != SEMI {
			equalsIdx++
		}

		// No equals found, skip to next parameter
		if equalsIdx >= len(params) || params[equalsIdx] != EQ {
			// Skip to next semicolon
			for pos < len(params) && params[pos] != SEMI {
				pos++
			}
			if pos < len(params) {
				pos++ // Skip semicolon
			}
			continue
		}

		// Extract parameter name
		paramName := TrimSpace(params[pos:equalsIdx])

		// Check if this is the parameter we're looking for
		if EqualsCaseInsensitive(paramName, name) {
			// Found it! Extract value
			pos = equalsIdx + 1 // Skip equals

			// Skip whitespace after equals
			for pos < len(params) && IsWhitespace(params[pos]) {
				pos++
			}

			if pos >= len(params) {
				return ""
			}

			// Check for quoted value
			if params[pos] == '"' {
				// Quoted value: find closing quote
				pos++ // Skip opening quote
				valueStart := pos
				for pos < len(params) && params[pos] != '"' {
					pos++
				}
				return params[valueStart:pos]
			}

			// Unquoted value: find semicolon or end
			valueStart := pos
			for pos < len(params) && params[pos] != SEMI {
				pos++
			}
			return TrimSpace(params[valueStart:pos])
		}

		// Not the parameter we want, skip to next
		pos = equalsIdx + 1
		// Skip value (quoted or unquoted)
		for pos < len(params) && IsWhitespace(params[pos]) {
			pos++
		}
		if pos < len(params) && params[pos] == '"' {
			// Skip quoted value
			pos++ // Skip opening quote
			for pos < len(params) && params[pos] != '"' {
				pos++
			}
			if pos < len(params) {
				pos++ // Skip closing quote
			}
		} else {
			// Skip unquoted value
			for pos < len(params) && params[pos] != SEMI {
				pos++
			}
		}
		// Skip semicolon
		if pos < len(params) && params[pos] == SEMI {
			pos++
		}
	}

	return ""
}

// FindHeaderBodySeparator finds the position where headers end and body begins.
// Looks for double line terminator: \r\n\r\n or \n\n
//
// Parameters:
//   - data: HTTP request/response bytes
//   - startOffset: Position to start searching from
//
// Returns:
//   - Position after the double line terminator (start of body)
//   - Returns -1 if not found
//
// Logic:
//  1. Search for CRLFCRLF (\r\n\r\n) sequence
//  2. Also search for LFLF (\n\n) sequence
//  3. Return position after separator
//  4. Handle edge case near end of data
//
// Example:
//
//	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY")
//	bodyStart := FindHeaderBodySeparator(request, 0)
//	// bodyStart = 38 (position after \r\n\r\n)
func FindHeaderBodySeparator(data []byte, startOffset int) int {
	dataLen := len(data)

	// Main search loop
	for pos := startOffset; pos < dataLen-3; pos++ {
		// Check for CRLFCRLF
		if data[pos] == CR && data[pos+1] == LF &&
			data[pos+2] == CR && data[pos+3] == LF {
			// Return position after separator
			return pos + 4
		}

		// Check for LFLF
		if data[pos] == LF && data[pos+1] == LF {
			// Return position after separator
			return pos + 2
		}
	}

	// Edge case: check last few bytes for LFLF
	if dataLen >= 3 {
		for pos := dataLen - 3; pos < dataLen-1; pos++ {
			if data[pos] == LF && data[pos+1] == LF {
				return pos + 2
			}
		}
	}

	// Not found
	return -1
}

// ExtractAllHeaders is a convenience function that extracts headers from
// an HTTP request/response, automatically finding the header section.
//
// Parameters:
//   - data: Complete HTTP request/response bytes
//
// Returns:
//   - headers: List of header lines including request/status line
//   - headerOffsets: Byte offset where each header starts
//   - bodyStart: Position where body begins (after headers)
//   - error: Any parsing error
//
// Logic:
//  1. Find header/body separator
//  2. Extract headers from start to separator
//  3. Return headers and body position
//
// Example:
//
//	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY")
//	headers, offsets, bodyStart, _ := ExtractAllHeaders(request)
//	// headers = ["GET / HTTP/1.1", "Host: example.com"]
//	// offsets = [0, 16]
//	// bodyStart = 38
func ExtractAllHeaders(data []byte) ([]string, []int, int, error) {
	if data == nil {
		return []string{}, []int{}, 0, nil
	}

	// Find header/body separator
	bodyStart := FindHeaderBodySeparator(data, 0)
	if bodyStart == -1 {
		// No separator found, treat entire data as headers
		bodyStart = len(data)
	}

	// Extract headers
	headers, offsets, err := ExtractHeaders(data, 0, bodyStart)

	return headers, offsets, bodyStart, err
}
