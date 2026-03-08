package httpmsg

// request_analyzer.go - Main HTTP request analyzer orchestrating all parsers
// Ported from:
//   - dz8.java: Main request info container and analysis orchestration
//   - c9s.java: Parameter extraction dispatcher (lines 369-571)
//   - glo.java: Request line parsing and helper methods
//   - hm.java: IRequestInfo implementation
//
// This is the MAIN ENTRY POINT that ties all components together:
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
// Ported from: dz8.java constructor and c9s.a(bi9, dz8) dispatcher method
// Source mapping:
//   - dz8.java: RequestInfo container (lines 6-61)
//   - c9s.a(bi9, dz8): Main analysis entry (lines 378-388)
//   - c9s.a(List<String>, int, bi9, Supplier): Full parameter extraction (lines 552-571)
//
// Algorithm (from Burp sources):
// 1. Extract headers and find body offset (glo.e() method)
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
	// Ported from: glo.e(bi9) method
	// Source: glo.java lines 118-124
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
	// Ported from: glo request line parsing
	// Source: c9s.java line 489-548 for path parsing, glo for request line
	method, url, httpVersion := parseRequestLine(headers[0])
	info.Method = method
	info.URL = url
	info.HTTPVersion = httpVersion

	// Step 2.5: Extract Host header value for HttpService
	info.HttpService = extractHostHeader(headers)

	// Step 3: Determine Content-Type from headers
	// Ported from: glo.a(List<String>, String, boolean) for header lookup
	// Source: c9s.java lines 379-381, 458-487
	contentType, boundary := ParseContentType(headers)
	info.ContentType = mapContentType(contentType)

	// Step 4: Parse URL query parameters from request line
	// Ported from: c9s.a(bi9) method for URL param extraction
	// Source: c9s.java lines 373-376
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
	// Ported from: c9s.c(bi9) method for path parameter extraction
	// Source: c9s.java lines 489-550, etq.java line 30-32
	pathParams, _ := ParsePathParameters(request)
	info.Parameters = append(info.Parameters, pathParams...)

	// Step 6: Extract cookies from Cookie headers
	// Ported from: c9s.b(bi9, Supplier) method for cookie extraction
	// Source: c9s.java lines 423-456
	cookieParams := extractCookieParameters(request, headers, headerOffsets)
	info.Parameters = append(info.Parameters, cookieParams...)

	// Step 7: Dispatch to appropriate body parser based on Content-Type
	// Ported from: c9s.a(bi9, h5p, String, int, Supplier) dispatcher
	// Source: c9s.java lines 399-417
	if bodyOffset < len(request) {
		info.HasBody = true
		bodyParams := parseBodyByContentType(request, bodyOffset, contentType, boundary)
		info.Parameters = append(info.Parameters, bodyParams...)
	}

	return info, nil
}

// parseRequestLine extracts method, URL, and HTTP version from request line.
// Ported from: glo.java request line parsing and c9s path parsing
// Source: c9s.java lines 489-548 for URL extraction
//
// Algorithm (from Burp):
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
// Ported from: Burp's HTTP version handling
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
// Ported from: c9s.a(bi9) method for URL parameter extraction
// Source: c9s.java lines 373-376
//
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

// parseBodyByContentType dispatches to appropriate body parser.
// Ported from: c9s.a(bi9, h5p, String, int, Supplier) dispatcher method
// Source: c9s.java lines 399-417 (switch statement)
//
// Algorithm (from c9s.java switch):
// - case 1 (URL_ENCODED): Parse URL-encoded body → ParamBody
// - case 2 (MULTIPART): Parse multipart/form-data → ParamBodyMultipart
// - case 4 (XML): Parse XML body → ParamXML
// - case 5 (JSON): Parse JSON body → ParamJSON
// - default: Return empty list
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
	// Switch based on content type (c9s.java lines 400-416)
	switch contentType {
	case "application/x-www-form-urlencoded":
		// case 1: URL_ENCODED (line 402)
		params, _ := ParseURLEncodedBody(request, bodyOffset)
		return params

	case "multipart/form-data":
		// case 2: MULTIPART (line 404)
		params, _ := ParseMultipartBody(request, bodyOffset, boundary)
		return params

	case "application/xml", "text/xml":
		// case 4: XML (line 410)
		params, _ := ParseXMLBody(request, bodyOffset)
		return params

	case "application/json", "text/json":
		// case 5: JSON (line 412)
		params, _ := ParseJSONBody(request, bodyOffset)
		return params

	default:
		// case 3, 6, 7: Unsupported or no body params (lines 406-408, 414-415)
		return []*Param{}
	}
}

// extractCookieParameters extracts cookies from Cookie headers.
// Ported from: c9s.b(bi9, Supplier) method for cookie extraction
// Source: c9s.java lines 423-456
//
// Algorithm (from c9s.java):
//  1. Find all "Cookie:" headers in request (lines 426-449)
//  2. For each Cookie header:
//     a. Skip "Cookie:" prefix and whitespace (lines 434-441)
//     b. Find end of header value (line 443-446)
//     c. Parse cookie values as name=value pairs (line 448)
//  3. Return all extracted cookie parameters
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

	// Loop through headers looking for "Cookie:" (c9s.java lines 429-452)
	for i := 0; i < len(headers); i++ {
		header := headers[i]

		// Check if this is a Cookie header (case-insensitive)
		if !StartsWithIgnoreCase(header, "Cookie:") {
			continue
		}

		// Find the start of cookie value (after "Cookie:" and spaces)
		// c9s.java lines 434-441
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
		// c9s.java line 448: a(e_q.COOKIE, var0, var4, var5, h5p.COOKIES, null, var1)
		cookieValue := header[cookieValueStart:]
		cookieParams := parseCookies(cookieValue, headerOffset+cookieValueStart)
		params = append(params, cookieParams...)
	}

	return params
}

// parseCookies parses Cookie header value into parameters.
// Format: "name1=value1; name2=value2; name3=value3"
// Ported from: c9s.a() method with e_q.COOKIE type
// Source: c9s.java lines 231-298 (case 3 in switch)
//
// Algorithm (from c9s.java lines 233-298):
// 1. Loop through cookie string (line 235)
// 2. Find name (before '=') (lines 240-259)
// 3. Find value (between '=' and ';') (lines 265-284)
// 4. Create parameter with ParamCookie type (line 286)
// 5. Skip whitespace and semicolons (lines 288-293)
// 6. Repeat until end of string
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

	// Main parsing loop (c9s.java lines 235-298)
	pos := 0
	length := len(cookieValue)

	for pos < length {
		// Skip leading whitespace and separators (c9s.java lines 288-293)
		for pos < length && (IsWhitespace(cookieValue[pos]) || cookieValue[pos] == SEMI) {
			pos++
		}

		if pos >= length {
			break
		}

		// Find name end ('=' or control char) (c9s.java lines 240-259)
		nameStart := pos
		nameEnd := -1

		for pos < length {
			if cookieValue[pos] == EQ {
				nameEnd = pos
				break
			}
			// Control character check (c9s.java lines 251-253)
			if cookieValue[pos] < 32 {
				break
			}
			pos++
		}

		// No '=' found or empty name, skip this cookie (c9s.java lines 261-263)
		if nameEnd == -1 || nameEnd == nameStart {
			// Skip to next semicolon
			for pos < length && cookieValue[pos] != SEMI && cookieValue[pos] >= 32 {
				pos++
			}
			continue
		}

		// Extract and decode name (cookies use form-encoding like query strings)
		name := DecodeQueryValue(cookieValue[nameStart:nameEnd])

		// Move past '=' (c9s.java line 265)
		pos = nameEnd + 1
		valueStart := pos
		valueEnd := -1

		// Find value end (';' or control char) (c9s.java lines 267-280)
		for pos < length {
			if cookieValue[pos] == SEMI || cookieValue[pos] < 32 {
				valueEnd = pos
				break
			}
			pos++
		}

		// If no separator found, value extends to end (c9s.java lines 282-284)
		if valueEnd == -1 {
			valueEnd = length
		}

		// Extract and decode value (cookies use form-encoding like query strings)
		value := DecodeQueryValue(cookieValue[valueStart:valueEnd])

		// Create parameter with ParamCookie type (c9s.java line 286)
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
		// c9s.java lines 288-293
		if pos < length && cookieValue[pos] == SEMI {
			pos++
		}
	}

	return params
}

// mapContentType converts MIME type string to ContentType enum.
// Ported from: h5p.java content type mapping and c9s.a() content type detection
// Source: c9s.java lines 458-487
//
// Algorithm (from c9s.java):
// 1. Check if body exists (lines 459-460, 484-486)
// 2. Try to detect from body content first (line 461)
// 3. Fall back to Content-Type header (lines 464-479)
// 4. Map string to h5p enum value
//
// Parameters:
//   - mimeType: MIME type string (e.g., "application/json")
//
// Returns:
//   - ContentType enum value
func mapContentType(mimeType string) ContentType {
	// Map MIME type to ContentType enum (c9s.java lines 465-479)
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
