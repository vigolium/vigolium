package httpmsg

// urlencoded_parser.go - URL-encoded body parameter parsing ported from Burp Suite
// Ported from: burp/c9s.java (URL_ENCODED body parameter parsing, lines 16-117, case 1)
//              burp/c9s.java (body parameter extraction, lines 399-417)
//              burp/glo.java (body extraction logic)
//
// CRITICAL: Uses ONLY loop-based parsing (NO REGEX)
// Follows Burp's char-by-char parameter detection for application/x-www-form-urlencoded bodies

// ParseURLEncodedBody parses application/x-www-form-urlencoded body parameters.
// This is the primary function for extracting parameters from POST body data.
//
// Ported from: c9s.java method a() for h5p.URL_ENCODED case (lines 20-117, case 1)
// Called from: c9s.java method a(bi9, h5p, String, int) (lines 399-417, case 1)
//
// Algorithm (from c9s.java lines 22-117):
//  1. Initialize position markers: pos, nameStart, nameEnd, valueStart, valueEnd
//  2. Loop through body bytes character by character
//  3. Skip leading CRLF/LF at parameter start (lines 41-47)
//  4. Find '=' character to separate name from value (lines 49-53)
//  5. Find '&' character to separate parameters (lines 56-63)
//  6. Handle edge cases: whitespace/control characters (lines 66-68)
//  7. Parse value portion after '=' (lines 85-106)
//  8. Create Parameter object with type ParamBody (line 110)
//  9. Move to next parameter (line 113)
//
// Example:
//
//	request := []byte("POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname=John&age=30")
//	bodyOffset := FindBodyOffset(request)
//	params, err := ParseURLEncodedBody(request, bodyOffset)
//	// Returns:
//	//   [0] = {Type: ParamBody, Name: "name", Value: "John", NameStart: 74, NameEnd: 78, ValueStart: 79, ValueEnd: 83}
//	//   [1] = {Type: ParamBody, Name: "age", Value: "30", NameStart: 84, NameEnd: 87, ValueStart: 88, ValueEnd: 90}
//
// Parameters:
//   - request: Complete HTTP request bytes including headers and body
//   - bodyOffset: Byte offset where body starts (from FindBodyOffset)
//
// Returns:
//   - List of Parameter objects with ParamBody type
//   - Error if parsing fails (currently never returns error for Burp compatibility)
func ParseURLEncodedBody(request []byte, bodyOffset int) ([]*Param, error) {
	if request == nil {
		return []*Param{}, nil
	}

	// Validate bodyOffset
	if bodyOffset < 0 || bodyOffset >= len(request) {
		return []*Param{}, nil
	}

	// Body extends from bodyOffset to end of request
	// From c9s.java line 402: a(e_q.BODY_PARAM_URL_ENCODED, var0, var3, var0.aF(), ...)
	// where var0.aF() returns the full length of the request
	bodyEnd := len(request)

	// Parse parameters using core URL-encoded parsing logic (c9s.java lines 22-117)
	// Key difference from query parsing: use ParamBody instead of ParamURL
	params := parseURLEncodedParameters(ParamBody, request, bodyOffset, bodyEnd)

	return params, nil
}

// GetBodyBytes extracts the body portion of an HTTP request as a byte slice.
// Helper function for working with request bodies.
//
// Ported from: glo.java body extraction logic
//
// Parameters:
//   - request: Complete HTTP request bytes
//   - bodyOffset: Byte offset where body starts
//
// Returns:
//   - Byte slice containing the body data
//   - Empty slice if bodyOffset is invalid
//
// Example:
//
//	request := []byte("POST / HTTP/1.1\r\n\r\nname=value")
//	bodyOffset := FindBodyOffset(request)
//	body := GetBodyBytes(request, bodyOffset)
//	// body = []byte("name=value")
func GetBodyBytes(request []byte, bodyOffset int) []byte {
	if request == nil {
		return []byte{}
	}

	if bodyOffset < 0 || bodyOffset >= len(request) {
		return []byte{}
	}

	return request[bodyOffset:]
}

// HasURLEncodedBody checks if an HTTP request has a URL-encoded body.
// Examines Content-Type header for application/x-www-form-urlencoded.
//
// Ported from: Request analysis logic in c9s.java and h5p.java
// Maps to: h5p.URL_ENCODED content type detection
//
// Algorithm:
//  1. Extract Content-Type header from headers list
//  2. Parse MIME type (before semicolon)
//  3. Compare against "application/x-www-form-urlencoded" (case-insensitive)
//
// Example:
//
//	headers := []string{
//		"POST / HTTP/1.1",
//		"Content-Type: application/x-www-form-urlencoded",
//		"Content-Length: 10",
//	}
//	hasURLEncoded := HasURLEncodedBody(headers)
//	// hasURLEncoded = true
//
// Parameters:
//   - headers: List of HTTP header lines (from ExtractHeaders or ExtractAllHeaders)
//
// Returns:
//   - true if Content-Type is application/x-www-form-urlencoded
//   - false otherwise
func HasURLEncodedBody(headers []string) bool {
	if len(headers) == 0 {
		return false
	}

	// Get Content-Type header using header parser
	contentType, _ := ParseContentType(headers)

	// Compare against application/x-www-form-urlencoded (case-insensitive)
	// From h5p.java: URL_ENCODED maps to "application/x-www-form-urlencoded"
	return EqualsCaseInsensitive(contentType, "application/x-www-form-urlencoded")
}

// ParseURLEncodedBodyString parses URL-encoded body from a string.
// Convenience function for testing and simple use cases.
//
// Parameters:
//   - body: URL-encoded body string (e.g., "name=value&foo=bar")
//
// Returns:
//   - List of Parameter objects with ParamBody type
//   - Error if parsing fails
//
// Example:
//
//	body := "username=admin&password=secret123&remember=on"
//	params, _ := ParseURLEncodedBodyString(body)
//	// Returns 3 parameters with ParamBody type
func ParseURLEncodedBodyString(body string) ([]*Param, error) {
	if body == "" {
		return []*Param{}, nil
	}

	bodyBytes := []byte(body)
	params := parseURLEncodedParameters(ParamBody, bodyBytes, 0, len(bodyBytes))

	return params, nil
}

// ExtractBodyParameters extracts all body parameters from a complete HTTP request.
// Automatically detects body offset and parses URL-encoded parameters.
//
// Ported from: c9s.java method a(bi9, h5p, String, int) for URL_ENCODED case
//
// Algorithm:
//  1. Find header/body separator (FindBodyOffset)
//  2. Validate Content-Type is application/x-www-form-urlencoded
//  3. Parse body parameters using parseURLEncodedParameters
//
// Example:
//
//	request := []byte("POST /api HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nkey=value")
//	params, bodyOffset, _ := ExtractBodyParameters(request)
//	// params contains extracted parameters with ParamBody type
//	// bodyOffset indicates where body starts
//
// Parameters:
//   - request: Complete HTTP request bytes
//
// Returns:
//   - params: List of extracted body parameters
//   - bodyOffset: Byte offset where body starts
//   - error: Any parsing error
func ExtractBodyParameters(request []byte) (params []*Param, bodyOffset int, err error) {
	if request == nil {
		return []*Param{}, 0, nil
	}

	// Extract headers and find body offset
	headers, _, bodyStart, err := ExtractAllHeaders(request)
	if err != nil {
		return []*Param{}, 0, err
	}

	// Check if body has URL-encoded content type
	if !HasURLEncodedBody(headers) {
		// Not URL-encoded body, return empty
		return []*Param{}, bodyStart, nil
	}

	// Parse URL-encoded body parameters
	params, err = ParseURLEncodedBody(request, bodyStart)

	return params, bodyStart, err
}

// GetBodyContentType determines the content type of the request body.
// Parses Content-Type header and maps to ContentType enum.
//
// Ported from: c9s.java method a(String, bi9, int) (lines 458-487)
//
//	h5p.java content type detection
//
// Algorithm (from c9s.java lines 458-487):
//  1. Check if body exists (bodyOffset != -1 and != length)
//  2. Try auto-detection using rp.a() heuristics
//  3. Fall back to Content-Type header parsing
//  4. Map MIME types to h5p enum values:
//     - "multipart" -> MULTIPART
//     - "xml" -> XML
//     - "json" -> JSON
//     - "application/x-amf" -> SER_AMF
//     - default -> URL_ENCODED
//
// Example:
//
//	headers := []string{"POST / HTTP/1.1", "Content-Type: application/json"}
//	bodyOffset := 38
//	contentType := GetBodyContentType(headers, []byte{}, bodyOffset)
//	// contentType = ContentTypeJSON
//
// Parameters:
//   - headers: List of HTTP header lines
//   - request: Complete HTTP request bytes
//   - bodyOffset: Offset where body starts
//
// Returns:
//   - ContentType enum value
func GetBodyContentType(headers []string, request []byte, bodyOffset int) ContentType {
	// If no body, return NONE (c9s.java lines 459-461)
	if bodyOffset == -1 || bodyOffset >= len(request) {
		return ContentTypeNone
	}

	// Parse Content-Type header (c9s.java line 464)
	contentTypeStr, _ := ParseContentType(headers)

	// If no Content-Type header, default to URL_ENCODED (c9s.java line 482)
	if contentTypeStr == "" {
		return ContentTypeURLEncoded
	}

	// Map MIME type to ContentType enum (c9s.java lines 465-480)
	// Check for multipart (line 465-466)
	if containsSubstring(contentTypeStr, "multipart") {
		return ContentTypeMultipart
	}

	// Check for XML (line 468-469)
	if containsSubstring(contentTypeStr, "xml") {
		return ContentTypeXML
	}

	// Check for JSON (line 471-472)
	if containsSubstring(contentTypeStr, "json") {
		return ContentTypeJSON
	}

	// Check for AMF (line 474-475)
	if containsSubstring(contentTypeStr, "application/x-amf") {
		return ContentTypeAMF
	}

	// Default to URL_ENCODED (c9s.java line 482)
	return ContentTypeURLEncoded
}

// containsSubstring checks if a string contains a substring (case-insensitive).
// Loop-based implementation (NO regex or strings.Contains).
//
// Parameters:
//   - s: String to search in
//   - substr: Substring to find
//
// Returns:
//   - true if substr found in s (case-insensitive)
func containsSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}

	if len(s) < len(substr) {
		return false
	}

	// Loop through possible starting positions
	for i := 0; i <= len(s)-len(substr); i++ {
		// Check if substring matches at this position
		match := true
		for j := 0; j < len(substr); j++ {
			if ToLower(s[i+j]) != ToLower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}

	return false
}
