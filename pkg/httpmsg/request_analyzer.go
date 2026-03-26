package httpmsg

// request_analyzer.go - Main HTTP request analyzer orchestrating all parsers
//
// This is the main entry point that ties all components together:
//   - ExtractAllHeaders() from header_parser.go
//   - ParseQueryString() from query_parser.go
//   - ParseURLEncodedBody() from urlencoded_parser.go
//   - ParseMultipartBody() from multipart_parser.go
//   - ParseJSONBody() from json_parser.go
//   - ParseXMLBody() from xml_parser.go
//   - ParseContentType() from header_parser.go
//   - RequestInfo struct from request_info.go
//   - Parameter struct from parameter.go

// AnalyzeRequest analyzes an HTTP request and returns parsed information.
// This is the main entry point that orchestrates all parsing components.
//
// Algorithm:
// 1. Extract headers and find body offset
// 2. Parse request line (method, URL, HTTP version) from first header
// 3. Determine Content-Type from headers
// 4. Parse URL query parameters from request line
// 5. Dispatch to appropriate body parser based on Content-Type:
//   - application/x-www-form-urlencoded → ParseURLEncodedBody
//   - multipart/form-data → ParseMultipartBody
//   - application/json → ParseJSONBody
//   - application/xml, text/xml → ParseXMLBody
//
// 6. Extract cookies from Cookie headers
// 7. Combine all parameters into single list
// 8. Populate and return RequestInfo
//
// Example:
//
//	request := []byte("POST /api?filter=active HTTP/1.1\r\n" +
//	    "Cookie: session=abc123; user=john\r\n" +
//	    "Content-Type: application/json\r\n\r\n" +
//	    `{"action":"update"}`)
//
//	info, err := AnalyzeRequest(request)
//	// info.Method = "POST"
//	// info.URL = "/api?filter=active"
//	// info.Parameters contains:
//	//   - 1 URL parameter (filter)
//	//   - 2 cookie parameters (session, user)
//	//   - 1 JSON parameter (action)
//
// Parameters:
//   - request: Complete HTTP request bytes including headers and body
//
// Returns:
//   - RequestInfo with all parsed data
//   - Error if parsing fails
func AnalyzeRequest(request []byte) (*RequestInfo, error) {
	info := NewRequestInfo()

	if len(request) == 0 {
		return info, nil
	}

	// Step 1: Extract headers and find body offset
	headers, headerOffsets, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}
	info.Headers = headers
	info.BodyOffset = bodyOffset

	// Skip if no headers found
	if len(headers) == 0 {
		return info, nil
	}

	// Step 2: Parse request line (first header)
	method, url, httpVersion := parseRequestLine(headers[0])
	info.Method = method
	info.URL = url
	info.HTTPVersion = httpVersion

	// Step 2.5: Extract Host header value for HttpService
	info.HttpService = extractHostHeader(headers)

	// Step 3: Determine Content-Type from headers
	contentType, boundary := ParseContentType(headers)
	info.ContentType = mapContentType(contentType)

	// Step 4: Parse URL query parameters from request line
	// Calculate URL offset in request: "METHOD URL HTTP..." -> URL starts after "METHOD "
	urlOffset := len(method) + 1 // +1 for space after method
	parsedUrlParams, _ := extractQueryParametersFromURL(url)

	// Adjust URL parameter offsets to be relative to full request
	// Offsets from parser are relative to URL string, need to add urlOffset
	for _, param := range parsedUrlParams {
		adjusted := param.WithAdjustedOffsets(urlOffset)
		info.Parameters = append(info.Parameters, adjusted)
	}

	// Step 5: Extract REST-style path parameters from URL
	pathParams, _ := ParsePathParameters(request)
	info.Parameters = append(info.Parameters, pathParams...)

	// Step 6: Extract cookies from Cookie headers
	cookieParams := extractCookieParameters(request, headers, headerOffsets)
	info.Parameters = append(info.Parameters, cookieParams...)

	// Step 7: Dispatch to appropriate body parser based on Content-Type
	if bodyOffset < len(request) {
		info.HasBody = true
		bodyParams := parseBodyByContentType(request, bodyOffset, contentType, boundary)
		info.Parameters = append(info.Parameters, bodyParams...)
	}

	return info, nil
}

// parseRequestLine extracts method, URL, and HTTP version from request line.
//
// Algorithm:
// 1. Split request line by spaces: "GET /path HTTP/1.1"
// 2. Extract method (first token)
// 3. Extract URL (second token)
// 4. Extract HTTP version (third token)
// 5. Convert HTTP version to integer (11 for HTTP/1.1, 20 for HTTP/2.0)
//
// Example:
//
//	method, url, version := parseRequestLine("GET /api?id=123 HTTP/1.1")
//	// method = "GET"
//	// url = "/api?id=123"
//	// version = 11
//
// Parameters:
//   - requestLine: First line of HTTP request
//
// Returns:
//   - method: HTTP method (GET, POST, etc.)
//   - url: Request URL/path
//   - httpVersion: Integer version (11 for HTTP/1.1, 20 for HTTP/2.0)
func parseRequestLine(requestLine string) (method string, url string, httpVersion int) {
	// Default values
	method = ""
	url = ""
	httpVersion = 11 // Default to HTTP/1.1

	if len(requestLine) == 0 {
		return
	}

	// Parse request line: "METHOD URL HTTP/VERSION"
	// Loop-based parsing (no strings.Split)
	pos := 0
	length := len(requestLine)

	// Extract method (first token before space)
	methodStart := pos
	for pos < length && requestLine[pos] != SPACE {
		pos++
	}
	if pos > methodStart {
		method = requestLine[methodStart:pos]
	}

	// Skip spaces
	for pos < length && requestLine[pos] == SPACE {
		pos++
	}

	// Extract URL (second token before space)
	urlStart := pos
	for pos < length && requestLine[pos] != SPACE {
		pos++
	}
	if pos > urlStart {
		url = requestLine[urlStart:pos]
	}

	// Skip spaces
	for pos < length && requestLine[pos] == SPACE {
		pos++
	}

	// Extract HTTP version (third token)
	versionStart := pos
	if pos < length {
		version := requestLine[versionStart:]
		// Parse "HTTP/1.1" or "HTTP/2.0" to integer
		httpVersion = parseHTTPVersion(version)
	}

	return
}

// parseHTTPVersion converts HTTP version string to integer.
//
// Algorithm:
// 1. Check for "HTTP/" prefix
// 2. Parse version number
// 3. Convert to integer: "1.1" → 11, "2.0" → 20
//
// Parameters:
//   - version: HTTP version string (e.g., "HTTP/1.1")
//
// Returns:
//   - Integer version (11 for HTTP/1.1, 20 for HTTP/2.0)
func parseHTTPVersion(version string) int {
	// Check for "HTTP/" prefix
	if len(version) < 5 || version[0:5] != "HTTP/" {
		return 11 // Default to HTTP/1.1
	}

	// Parse version number after "HTTP/"
	versionNum := version[5:]

	if len(versionNum) == 0 {
		return 11 // Default to HTTP/1.1
	}

	// Handle "2" or "2.0" → 20 (HTTP/2)
	if versionNum[0] == '2' {
		return 20
	}

	// Handle "1.1" → 11
	if len(versionNum) >= 3 && versionNum[0] == '1' && versionNum[1] == '.' && versionNum[2] == '1' {
		return 11
	}

	// Handle "1.0" → 10
	if len(versionNum) >= 3 && versionNum[0] == '1' && versionNum[1] == '.' && versionNum[2] == '0' {
		return 10
	}

	// Handle "1" → 11 (default to HTTP/1.1)
	if versionNum[0] == '1' {
		return 11
	}

	// Default to HTTP/1.1
	return 11
}

// extractQueryParametersFromURL extracts query parameters from URL string.
// This is a wrapper around ParseQueryString that works with URL strings.
//
// Parameters:
//   - url: URL string (e.g., "/api?id=123&name=test")
//
// Returns:
//   - List of Param objects with ParamURL type
//   - Error if parsing fails
func extractQueryParametersFromURL(url string) ([]*Param, error) {
	if url == "" {
		return []*Param{}, nil
	}

	// Convert URL string to bytes
	urlBytes := []byte(url)

	// Use existing ParseQueryString function
	return ParseQueryString(urlBytes)
}

// parseBodyByContentType dispatches to appropriate body parser based on content type.
//
// Parameters:
//   - request: Complete HTTP request bytes
//   - bodyOffset: Byte offset where body starts
//   - contentType: MIME type string (e.g., "application/json")
//   - boundary: Multipart boundary string (if applicable)
//
// Returns:
//   - List of Param objects extracted from body
func parseBodyByContentType(request []byte, bodyOffset int, contentType, boundary string) []*Param {
	switch contentType {
	case "application/x-www-form-urlencoded":
		params, _ := ParseURLEncodedBody(request, bodyOffset)
		return params

	case "multipart/form-data":
		params, _ := ParseMultipartBody(request, bodyOffset, boundary)
		return params

	case "application/xml", "text/xml":
		params, _ := ParseXMLBody(request, bodyOffset)
		return params

	case "application/json", "text/json":
		params, _ := ParseJSONBody(request, bodyOffset)
		return params

	default:
		return []*Param{}
	}
}

// extractCookieParameters extracts cookies from Cookie headers.
//
// Cookie format: "Cookie: name1=value1; name2=value2"
// Each cookie becomes a ParamCookie parameter.
//
// Parameters:
//   - request: Complete HTTP request bytes
//   - headers: List of header strings
//   - headerOffsets: Byte offsets of each header
//
// Returns:
//   - List of Param objects with ParamCookie type
func extractCookieParameters(request []byte, headers []string, headerOffsets []int) []*Param {
	params := []*Param{}

	// Loop through headers looking for "Cookie:"
	for i := 0; i < len(headers); i++ {
		header := headers[i]

		// Check if this is a Cookie header (case-insensitive)
		if !StartsWithIgnoreCase(header, "Cookie:") {
			continue
		}

		// Find the start of cookie value (after "Cookie:" and spaces)
		cookieValueStart := 7 // Length of "Cookie:"
		for cookieValueStart < len(header) && IsWhitespace(header[cookieValueStart]) {
			cookieValueStart++
		}

		if cookieValueStart >= len(header) {
			continue
		}

		// Calculate absolute offset in request
		// headerOffsets[i] is the start of the header line in request bytes
		headerOffset := 0
		if i < len(headerOffsets) {
			headerOffset = headerOffsets[i]
		}

		// Parse cookies from header value
		cookieValue := header[cookieValueStart:]
		cookieParams := parseCookies(cookieValue, headerOffset+cookieValueStart)
		params = append(params, cookieParams...)
	}

	return params
}

// parseCookies parses Cookie header value into parameters.
// Format: "name1=value1; name2=value2; name3=value3"
//
// Parameters:
//   - cookieValue: Cookie header value (e.g., "session=abc; user=john")
//   - headerOffset: Byte offset where cookie value starts in request
//
// Returns:
//   - List of Param objects with ParamCookie type
func parseCookies(cookieValue string, headerOffset int) []*Param {
	params := []*Param{}

	if len(cookieValue) == 0 {
		return params
	}

	// Main parsing loop
	pos := 0
	length := len(cookieValue)

	for pos < length {
		// Skip leading whitespace and separators
		for pos < length && (IsWhitespace(cookieValue[pos]) || cookieValue[pos] == SEMI) {
			pos++
		}

		if pos >= length {
			break
		}

		// Find name end ('=' or control char)
		nameStart := pos
		nameEnd := -1

		for pos < length {
			if cookieValue[pos] == EQ {
				nameEnd = pos
				break
			}
			// Control character check
			if cookieValue[pos] < 32 {
				break
			}
			pos++
		}

		// No '=' found or empty name, skip this cookie
		if nameEnd == -1 || nameEnd == nameStart {
			// Skip to next semicolon
			for pos < length && cookieValue[pos] != SEMI && cookieValue[pos] >= 32 {
				pos++
			}
			continue
		}

		// Extract and decode name (cookies use form-encoding like query strings)
		name := DecodeQueryValue(cookieValue[nameStart:nameEnd])

		// Move past '='
		pos = nameEnd + 1
		valueStart := pos
		valueEnd := -1

		// Find value end (';' or control char)
		for pos < length {
			if cookieValue[pos] == SEMI || cookieValue[pos] < 32 {
				valueEnd = pos
				break
			}
			pos++
		}

		// If no separator found, value extends to end
		if valueEnd == -1 {
			valueEnd = length
		}

		// Extract and decode value (cookies use form-encoding like query strings)
		value := DecodeQueryValue(cookieValue[valueStart:valueEnd])

		// Create parameter with ParamCookie type
		// Calculate absolute offsets in request
		param := NewParsedParam(
			ParamCookie,
			name,
			value,
			headerOffset+nameStart,
			headerOffset+nameEnd,
			headerOffset+valueStart,
			headerOffset+valueEnd,
		)
		params = append(params, param)

		// Continue to next cookie (advance past separator)
		if pos < length && cookieValue[pos] == SEMI {
			pos++
		}
	}

	return params
}

// mapContentType converts MIME type string to ContentType enum.
//
// Parameters:
//   - mimeType: MIME type string (e.g., "application/json")
//
// Returns:
//   - ContentType enum value
func mapContentType(mimeType string) ContentType {
	// Map MIME type to ContentType enum
	switch mimeType {
	case "application/x-www-form-urlencoded":
		return ContentTypeURLEncoded

	case "multipart/form-data":
		return ContentTypeMultipart

	case "application/json":
		return ContentTypeJSON

	case "application/xml", "text/xml":
		return ContentTypeXML

	case "application/x-amf":
		return ContentTypeAMF

	default:
		// Unknown or no content type
		return ContentTypeUnknown
	}
}

// StartsWithIgnoreCase checks if string starts with prefix (case-insensitive).
// Helper function for header matching.
func StartsWithIgnoreCase(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}

	for i := 0; i < len(prefix); i++ {
		if ToLower(s[i]) != ToLower(prefix[i]) {
			return false
		}
	}

	return true
}

// extractHostHeader extracts the Host header value from headers list.
// Returns empty string if Host header is not found.
func extractHostHeader(headers []string) string {
	for i := 1; i < len(headers); i++ {
		header := headers[i]
		if !StartsWithIgnoreCase(header, "Host:") {
			continue
		}

		// Skip "Host:" and whitespace
		valueStart := 5
		for valueStart < len(header) && IsWhitespace(header[valueStart]) {
			valueStart++
		}

		if valueStart >= len(header) {
			return ""
		}

		return header[valueStart:]
	}

	return ""
}
