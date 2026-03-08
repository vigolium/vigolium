package httpmsg

// request_builder_headers.go - HTTP header manipulation functions
// Ported from: burp/glo.java (header operations)
//
// This file contains ALL header operations:
// - Burp Standard API: AddHeader, RemoveHeader, UpdateContentLength
// - Extensions: Replace, Get, Has, GetAll, GetByPrefix, ContentType, Host

// ==================== BURP STANDARD API: HEADER OPERATIONS ====================

// AddHeader adds a new header to an HTTP message.
// Ported from: glo.java a(bi9, String) method (lines 77-103)
//
//	Which calls a(bi9, byte[], boolean) (lines 81-103)
//
// Algorithm (from glo.java lines 81-103):
//  1. Find header end position (before separator) (lines 85-88)
//  2. Write message up to that position (line 93)
//  3. Write new header bytes (line 94)
//  4. Write CRLF (lines 95-96)
//  5. Write rest of message from that position onward (line 97)
//  6. Return new message (line 98)
//
// Note: The key is that var3=false in glo.java line 46 returns i+2,
// which is the position BEFORE the final CRLF (after the first CRLF
// of the CRLFCRLF separator). This is where we insert the header.
//
// Parameters:
//   - message: Original HTTP message
//   - name: Header name
//   - value: Header value
//
// Returns:
//   - Modified HTTP message with new header
//   - Error if message is malformed
//
// Example:
//
//	request := []byte("GET / HTTP/1.1\r\n\r\n")
//	modified, _ := AddHeader(request, "Host", "example.com")
//	// Returns: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
func AddHeader(message []byte, name, value string) ([]byte, error) {
	if message == nil {
		return nil, nil
	}

	// Build header line "Name: Value"
	headerLine := buildHeaderLine(name, value)
	headerBytes := []byte(headerLine)

	// Find header end position (glo.java lines 85-88)
	// This is the position BEFORE the final CRLF of the separator
	headerEndPos := findHeaderEndPosition(message, 0)
	if headerEndPos == -1 {
		// No separator found, treat entire message as headers
		headerEndPos = len(message)
	}

	// Calculate new message size
	newSize := headerEndPos + len(headerBytes) + 2 + (len(message) - headerEndPos)
	result := make([]byte, 0, newSize)

	// Write message up to header end (glo.java line 93)
	result = append(result, message[:headerEndPos]...)

	// Write new header (glo.java line 94)
	result = append(result, headerBytes...)

	// Write CRLF (glo.java lines 95-96)
	result = append(result, CR, LF)

	// Write rest of message from header end (glo.java line 97)
	result = append(result, message[headerEndPos:]...)

	return result, nil
}

// RemoveHeader removes a header from an HTTP message.
// Ported from: glo.java a(bi9, String, boolean, String, boolean, boolean) method
//
//	(lines 228-293) called via parameter manipulation
//
// Algorithm (from glo.java lines 237-244):
//  1. Find header/body separator (lines 232-233)
//  2. Extract all headers (line 238)
//  3. Remove matching header using a() helper (line 243)
//  4. Rebuild message with ec5.a() (line 244)
//
// The actual removal happens in glo.a() lines 247-293:
//  1. Loop through headers (lines 262-287)
//  2. Find matching header (case-insensitive) (line 264)
//  3. Remove header from list (line 266)
//  4. Rebuild message (line 244 in caller)
//
// Parameters:
//   - message: Original HTTP message
//   - name: Header name to remove (case-insensitive)
//
// Returns:
//   - Modified HTTP message without the header
//   - Error if message is malformed
//
// Example:
//
//	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
//	modified, _ := RemoveHeader(request, "User-Agent")
//	// Returns: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
func RemoveHeader(message []byte, name string) ([]byte, error) {
	if message == nil {
		return nil, nil
	}

	// Extract all headers and body offset
	headers, _, bodyOffset, err := ExtractAllHeaders(message)
	if err != nil {
		return nil, err
	}

	// Filter out matching header (case-insensitive)
	// From glo.java lines 262-287
	filteredHeaders := make([]string, 0, len(headers))
	for _, header := range headers {
		// Extract header name (everything before ':')
		headerName := extractHeaderName(header)

		// Skip matching header (case-insensitive comparison)
		if EqualsCaseInsensitive(headerName, name) {
			continue
		}

		filteredHeaders = append(filteredHeaders, header)
	}

	// Get body if present
	var body []byte
	if bodyOffset < len(message) {
		body = message[bodyOffset:]
	}

	// Rebuild message (ec5.java a() method)
	return BuildHttpMessage(filteredHeaders, body), nil
}

// UpdateContentLength updates or adds Content-Length header.
// Ported from: glo.java d(bi9) method (lines 295-312)
//
// Algorithm (from glo.java lines 295-312):
//  1. Find body offset with strict CRLF CRLF check (line 299)
//  2. If no separator, return unchanged (lines 300-301)
//  3. Extract headers (line 303)
//  4. Calculate body length: total - offset - 2 (line 304)
//  5. If body exists OR Content-Length header exists (line 305):
//     - Update/add Content-Length header (line 306)
//  6. Return updated message (line 309)
//
// Parameters:
//   - message: HTTP message
//
// Returns:
//   - Message with correct Content-Length
//   - Error if message is malformed
//
// Example:
//
//	request := []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\ntest")
//	updated, _ := UpdateContentLength(request)
//	// Returns: "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"
func UpdateContentLength(message []byte) ([]byte, error) {
	if message == nil {
		return nil, nil
	}

	// Find body offset with strict CRLF CRLF (glo.java line 299)
	// Uses var2=true which means strict CRLF CRLF checking
	bodyOffset := findBodyOffsetStrict(message, 0)
	if bodyOffset == -1 {
		// No separator found, return unchanged (glo.java lines 300-301)
		return message, nil
	}

	// Extract headers (glo.java line 303)
	headers, _, _, err := ExtractAllHeaders(message)
	if err != nil {
		return nil, err
	}

	// Calculate body length (glo.java line 304)
	// Note: Burp subtracts 2 from the calculation, but this is already
	// accounted for since bodyOffset points AFTER the separator
	bodyLength := len(message) - bodyOffset

	// Check if we need to add/update Content-Length (glo.java line 305)
	// Only if body exists OR Content-Length header already present
	hasContentLength := Header(headers, "Content-Length") != ""

	if bodyLength > 0 || hasContentLength {
		// Remove existing Content-Length
		headers = removeHeaderFromList(headers, "Content-Length")

		// Add new Content-Length with correct value
		// Using loop-based int to string conversion
		contentLengthValue := intToString(bodyLength)
		headers = append(headers, "Content-Length: "+contentLengthValue)
	}

	// Get body if present
	var body []byte
	if bodyOffset < len(message) {
		body = message[bodyOffset:]
	}

	// Rebuild message
	return BuildHttpMessage(headers, body), nil
}

// ==================== HELPER FUNCTIONS ====================

// findHeaderEndPosition finds the position where headers end (before final separator CRLF).
// Ported from: glo.java a(bi9, int, boolean, boolean) with var3=false
// (lines 37-75, specifically returning i+2 at line 46 and i+1 at line 58)
//
// Algorithm (glo.java lines 51-61 with var3=false):
//  1. Search for CRLF CRLF sequence (13 10 13 10)
//  2. If found, return i+2 (position after first CRLF, before second CRLF)
//  3. Also check for LF LF sequence (10 10)
//  4. If found, return i+1 (position after first LF, before second LF)
//  5. Return -1 if not found
//
// This is used by AddHeader to insert headers before the final separator.
func findHeaderEndPosition(message []byte, startOffset int) int {
	if message == nil {
		return -1
	}

	length := len(message)

	// Search for CRLF CRLF or LF LF (glo.java lines 51-61)
	for i := startOffset; i < length-3; i++ {
		// Check for CRLF CRLF (13 10 13 10)
		if message[i] == CR && message[i+1] == LF &&
			message[i+2] == CR && message[i+3] == LF {
			// var3=false means return position after first CRLF (glo.java line 46)
			return i + 2
		}

		// Check for LF LF (10 10)
		if message[i] == LF && message[i+1] == LF {
			// var3=false means return position after first LF (glo.java line 58)
			return i + 1
		}
	}

	// Edge case: check last few bytes for LF LF (glo.java lines 63-70)
	if length >= 3 {
		for i := length - 3; i < length-1; i++ {
			if message[i] == LF && message[i+1] == LF {
				// var3=false means return position after first LF
				return i + 1
			}
		}
	}

	return -1
}

// findBodyOffsetStrict finds body offset with strict CRLF CRLF checking.
// Ported from: glo.java a(bi9, int, boolean, boolean) with var2=true
// (lines 37-75, specifically the var2=true path at lines 43-49)
//
// Algorithm (glo.java lines 43-49):
//  1. Only look for CRLF CRLF sequence (13 10 13 10)
//  2. Do NOT accept LF LF as alternative
//  3. Return offset after separator (var3=false means return separator start + 2)
//  4. Return -1 if not found
//
// This is used by UpdateContentLength which needs strict checking.
func findBodyOffsetStrict(message []byte, startOffset int) int {
	if message == nil {
		return -1
	}

	length := len(message)

	// Search for CRLF CRLF only (glo.java lines 44-48)
	for i := startOffset; i < length-3; i++ {
		if message[i] == CR && message[i+1] == LF &&
			message[i+2] == CR && message[i+3] == LF {
			// var3=false means return offset BEFORE final CRLF (line 46)
			// which is separator start + 2 (after first CRLF)
			return i + 4 // Actually for body start we want after all 4 bytes
		}
	}

	return -1
}

// removeHeaderFromList removes a header from a header list (case-insensitive).
// Helper for UpdateContentLength and RemoveHeader.
//
// Algorithm:
//  1. Loop through headers
//  2. Skip matching header name (case-insensitive)
//  3. Keep all other headers
func removeHeaderFromList(headers []string, name string) []string {
	result := make([]string, 0, len(headers))
	for _, header := range headers {
		headerName := extractHeaderName(header)
		if !EqualsCaseInsensitive(headerName, name) {
			result = append(result, header)
		}
	}
	return result
}

// ==================== EXTENSION API: HEADER OPERATIONS ====================

// ReplaceHeader atomically replaces a header value (remove + add).
// Extension to Burp API - provides atomic header replacement.
//
// Algorithm:
//  1. Remove existing header if present
//  2. Add new header
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Header name
//   - value: New header value
//
// Returns:
//   - Modified request with replaced header
//   - Error if request malformed
//
// Example:
//
//	modified, _ := ReplaceHeader(request, "User-Agent", "CustomAgent/1.0")
func ReplaceHeader(request []byte, name, value string) ([]byte, error) {
	// Remove existing header (ignores if not present)
	modified, err := RemoveHeader(request, name)
	if err != nil {
		return nil, err
	}

	// Add new header
	return AddHeader(modified, name, value)
}

// AddOrReplaceHeader adds header if not exists, replaces if exists.
// Extension to Burp API - provides conditional header operation.
//
// Algorithm:
//  1. Check if header exists
//  2. If exists, replace; if not, add
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Header name
//   - value: Header value
//
// Returns:
//   - Modified request with header set
//   - Error if request malformed
//
// Example:
//
//	modified, _ := AddOrReplaceHeader(request, "Authorization", "Bearer token")
func AddOrReplaceHeader(request []byte, name, value string) ([]byte, error) {
	return ReplaceHeader(request, name, value)
}

// AddHeaderIfNotExists adds a header only if it doesn't already exist.
// Extension to Burp API - provides conditional add operation.
//
// Algorithm:
//  1. Check if header exists
//  2. If not exists, add header
//  3. If exists, return unchanged
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Header name
//   - value: Header value
//
// Returns:
//   - Modified request (unchanged if header exists)
//   - Error if request malformed
//
// Example:
//
//	modified, _ := AddHeaderIfNotExists(request, "Accept", "application/json")
func AddHeaderIfNotExists(request []byte, name, value string) ([]byte, error) {
	exists, err := HasHeader(request, name)
	if err != nil {
		return nil, err
	}

	if exists {
		return request, nil
	}

	return AddHeader(request, name, value)
}

// GetHeaderValue extracts a header value directly from request bytes.
// Extension to Burp API - provides direct header access without pre-parsing.
//
// Algorithm:
//  1. Extract headers using ExtractAllHeaders
//  2. Use GetHeader to find value
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Header name (case-insensitive)
//
// Returns:
//   - Header value (empty string if not found)
//   - Error if request malformed
//
// Example:
//
//	contentType, _ := GetHeaderValue(request, "Content-Type")
func GetHeaderValue(request []byte, name string) (string, error) {
	headers, _, _, err := ExtractAllHeaders(request)
	if err != nil {
		return "", err
	}

	return Header(headers, name), nil
}

// HasHeader checks if a header exists in the request.
// Extension to Burp API - provides header existence check.
//
// Algorithm:
//  1. Get header value
//  2. Return true if not empty
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Header name (case-insensitive)
//
// Returns:
//   - true if header exists
//   - Error if request malformed
//
// Example:
//
//	hasAuth, _ := HasHeader(request, "Authorization")
func HasHeader(request []byte, name string) (bool, error) {
	value, err := GetHeaderValue(request, name)
	if err != nil {
		return false, err
	}

	return value != "", nil
}

// GetAllHeaderValues returns all values for a header (for multi-value headers).
// Extension to Burp API - supports headers that can appear multiple times.
//
// Algorithm:
//  1. Extract all headers
//  2. Loop through and collect all matching header values
//  3. Return as slice
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Header name (case-insensitive)
//
// Returns:
//   - Slice of all values for the header
//   - Error if request malformed
//
// Example:
//
//	setCookies, _ := GetAllHeaderValues(request, "Set-Cookie")
func GetAllHeaderValues(request []byte, name string) ([]string, error) {
	headers, _, _, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	var values []string
	for i := 1; i < len(headers); i++ { // Skip request line at index 0
		headerName := extractHeaderName(headers[i])
		if EqualsCaseInsensitive(headerName, name) {
			// Extract value after colon
			for j := 0; j < len(headers[i]); j++ {
				if headers[i][j] == ':' {
					value := headers[i][j+1:]
					// Trim leading space
					if len(value) > 0 && value[0] == ' ' {
						value = value[1:]
					}
					values = append(values, value)
					break
				}
			}
		}
	}

	return values, nil
}

// GetHeadersByPrefix returns all headers matching a prefix.
// Extension to Burp API - useful for getting all X-* headers, etc.
//
// Algorithm:
//  1. Extract all headers
//  2. Loop through and collect headers starting with prefix
//  3. Return as slice (full "Name: Value" format)
//
// Parameters:
//   - request: HTTP request bytes
//   - prefix: Header name prefix (case-insensitive)
//
// Returns:
//   - Slice of matching headers in "Name: Value" format
//   - Error if request malformed
//
// Example:
//
//	customHeaders, _ := GetHeadersByPrefix(request, "X-")
func GetHeadersByPrefix(request []byte, prefix string) ([]string, error) {
	headers, _, _, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	var matching []string
	prefixLower := ToLowerString(prefix)

	for i := 1; i < len(headers); i++ { // Skip request line
		headerName := extractHeaderName(headers[i])
		headerNameLower := ToLowerString(headerName)

		// Check if starts with prefix
		if len(headerNameLower) >= len(prefixLower) {
			match := true
			for j := 0; j < len(prefixLower); j++ {
				if headerNameLower[j] != prefixLower[j] {
					match = false
					break
				}
			}
			if match {
				matching = append(matching, headers[i])
			}
		}
	}

	return matching, nil
}

// GetContentType extracts the Content-Type header value.
// Extension to Burp API - convenience wrapper for common header.
//
// Algorithm:
//  1. Call GetHeaderValue for "Content-Type"
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Content-Type value
//   - Error if request malformed
//
// Example:
//
//	contentType, _ := GetContentType(request)
func GetContentType(request []byte) (string, error) {
	return GetHeaderValue(request, "Content-Type")
}

// SetContentType sets the Content-Type header.
// Extension to Burp API - convenience wrapper for common header.
//
// Algorithm:
//  1. Call ReplaceHeader for "Content-Type"
//
// Parameters:
//   - request: HTTP request bytes
//   - contentType: Content-Type value
//
// Returns:
//   - Modified request with Content-Type set
//   - Error if request malformed
//
// Example:
//
//	modified, _ := SetContentType(request, "application/json")
func SetContentType(request []byte, contentType string) ([]byte, error) {
	return ReplaceHeader(request, "Content-Type", contentType)
}

// GetHost extracts the Host header value.
// Extension to Burp API - convenience wrapper for common header.
//
// Algorithm:
//  1. Call GetHeaderValue for "Host"
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Host value
//   - Error if request malformed
//
// Example:
//
//	host, _ := GetHost(request)
func GetHost(request []byte) (string, error) {
	return GetHeaderValue(request, "Host")
}

// AppendToHeader appends a value to an existing header.
// If header doesn't exist, returns request unchanged.
// Ported from: Utilities.java appendToHeader() (lines 788-794)
//
// Algorithm:
//  1. Find header offsets using GetHeaderOffsets
//  2. If header not found, return unchanged
//  3. Insert append value at the end of header value
//  4. Return modified request
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Header name to append to
//   - appendValue: Value to append (e.g., ", text/html")
//
// Returns:
//   - Modified request with appended header value
//   - Error if request malformed
//
// Example:
//
//	req, _ := AppendToHeader(request, "Accept", ", text/html")
//	// "Accept: text/plain" → "Accept: text/plain, text/html"
func AppendToHeader(request []byte, name, appendValue string) ([]byte, error) {
	if request == nil || name == "" {
		return request, nil
	}

	// Find header offsets
	offsets := GetHeaderOffsets(request, name)
	if offsets == nil {
		// Header not found, return unchanged
		return request, nil
	}

	// offsets = [lineStart, valueStart, valueEnd]
	valueEnd := offsets[2]

	// Build new request with appended value
	appendBytes := []byte(appendValue)
	newSize := len(request) + len(appendBytes)
	result := make([]byte, 0, newSize)

	// Write up to value end
	result = append(result, request[:valueEnd]...)

	// Write append value
	result = append(result, appendBytes...)

	// Write rest of request
	result = append(result, request[valueEnd:]...)

	return result, nil
}

// GetHeaderOffsets returns [lineStart, valueStart, valueEnd] offsets for a header.
// Ported from: Utilities.java getHeaderOffsets() (lines 883-917)
//
// Algorithm:
//  1. Search through headers line by line
//  2. Find header with matching name (case-insensitive)
//  3. Return offsets: [lineStart, valueStart, valueEnd]
//     - lineStart: Position where header line begins
//     - valueStart: Position where header value begins (after ": ")
//     - valueEnd: Position where header value ends (before CRLF)
//  4. Return nil if header not found
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Header name to find (case-insensitive)
//
// Returns:
//   - []int{lineStart, valueStart, valueEnd} or nil if not found
//
// Example:
//
//	offsets := GetHeaderOffsets(request, "Host")
//	// For "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
//	// offsets = [16, 22, 33] (line at 16, value "example.com" from 22 to 33)
func GetHeaderOffsets(request []byte, name string) []int {
	if request == nil || name == "" {
		return nil
	}

	length := len(request)
	lineStart := 0

	// Skip first line (request line)
	for i := 0; i < length-1; i++ {
		if request[i] == LF {
			lineStart = i + 1
			break
		}
	}

	// Search through headers
	for lineStart < length {
		// Find end of line (LF)
		lineEnd := lineStart
		for lineEnd < length && request[lineEnd] != LF {
			lineEnd++
		}

		// Check for empty line (end of headers)
		if lineEnd == lineStart || (lineEnd == lineStart+1 && request[lineStart] == CR) {
			break
		}

		// Find colon position
		colonPos := -1
		for i := lineStart; i < lineEnd; i++ {
			if request[i] == ':' {
				colonPos = i
				break
			}
		}

		if colonPos != -1 {
			// Extract header name
			headerName := string(request[lineStart:colonPos])

			// Case-insensitive comparison
			if EqualsCaseInsensitive(headerName, name) {
				// Found the header
				// valueStart is after colon (and optional space)
				valueStart := colonPos + 1
				if valueStart < lineEnd && request[valueStart] == ' ' {
					valueStart++
				}

				// valueEnd is before CRLF
				valueEnd := lineEnd
				if valueEnd > valueStart && request[valueEnd-1] == CR {
					valueEnd--
				}

				return []int{lineStart, valueStart, valueEnd}
			}
		}

		// Move to next line
		lineStart = lineEnd + 1
	}

	return nil
}
