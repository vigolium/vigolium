package httpmsg

// request_builder_core.go - Core HTTP message building utilities
// Ported from: burp/ec5.java, burp/d4n.java
//
// CRITICAL: Uses ONLY loop-based parsing (NO REGEX)
// Follows Burp's byte-by-byte message construction

// BuildHttpMessage builds an HTTP message from headers and body.
// Ported from: ec5.java a(List<String>, bi9) method (lines 38-64)
//
//	d4n.java buildHttpMessage() method (lines 218-233)
//
// Algorithm (from ec5.java lines 38-64):
//  1. Write each header line followed by CRLF (lines 46-52)
//  2. Write additional CRLF to separate headers from body (line 54)
//  3. Append body bytes if present (lines 55-57)
//  4. Return complete message as byte array (line 59)
//
// Parameters:
//   - headers: List of HTTP headers (including request/status line as first element)
//   - body: Message body bytes (can be nil for no body)
//
// Returns:
//   - Complete HTTP message as byte array
//
// Example:
//
//	headers := []string{"GET / HTTP/1.1", "Host: example.com"}
//	body := []byte("test data")
//	message := BuildHttpMessage(headers, body)
//	// Returns: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\ntest data"
func BuildHttpMessage(headers []string, body []byte) []byte {
	if headers == nil {
		return body
	}

	// Pre-calculate size for efficiency
	// Each header + CRLF, plus final CRLF, plus body
	totalSize := 2 // Final CRLF
	for _, header := range headers {
		totalSize += len(header) + 2 // header + CRLF
	}
	if body != nil {
		totalSize += len(body)
	}

	// Build message (ec5.java lines 43-59)
	result := make([]byte, 0, totalSize)

	// Write headers with CRLF (ec5.java lines 46-52)
	for _, header := range headers {
		// Convert string to bytes (net.portswigger.h9.a())
		result = append(result, []byte(header)...)
		// Write CRLF (net.portswigger.ky.c which is \r\n)
		result = append(result, CR, LF)
	}

	// Write final CRLF to separate headers from body (ec5.java line 54)
	result = append(result, CR, LF)

	// Append body if present (ec5.java lines 55-57)
	if body != nil {
		result = append(result, body...)
	}

	return result
}

// BuildHttpRequest builds a basic HTTP GET request for a URL.
// Ported from: d4n.java buildHttpRequest() method (lines 414-432)
//
// Algorithm (from d4n.java):
//  1. Parse URL to extract components (line 419)
//  2. Build request using internal request builder (lines 422)
//  3. Return as byte array (line 422)
//
// NOTE: Burp uses java.net.URL and internal request builder.
// We use our ParseURL and build manually to avoid stdlib net/url.
//
// Parameters:
//   - urlStr: Complete URL string (e.g., "http://example.com:8080/path")
//
// Returns:
//   - HTTP GET request bytes
//   - Error if URL parsing fails
//
// Example:
//
//	request, _ := BuildHttpRequest("http://example.com/api")
//	// Returns: "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
func BuildHttpRequest(urlStr string) ([]byte, error) {
	// Parse URL using our loop-based parser
	parsed, err := ParseURL([]byte(urlStr))
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, nil
	}

	// Build request line: "GET /path HTTP/1.1"
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	// Add query string if present
	if parsed.Query != "" {
		path = path + "?" + parsed.Query
	}

	requestLine := "GET " + path + " HTTP/1.1"

	// Build Host header
	host := parsed.Host
	if parsed.Port > 0 {
		// Only include port if non-default
		isDefaultPort := (parsed.Protocol == "http" && parsed.Port == 80) ||
			(parsed.Protocol == "https" && parsed.Port == 443)
		if !isDefaultPort {
			host = host + ":" + intToString(parsed.Port)
		}
	}

	headers := []string{
		requestLine,
		"Host: " + host,
	}

	// Build message with no body
	return BuildHttpMessage(headers, nil), nil
}

// ==================== SHARED HELPER FUNCTIONS ====================

// buildHeaderLine creates a "Name: Value" header line.
// Ported from: Standard HTTP header format
func buildHeaderLine(name, value string) string {
	return name + ": " + value
}

// intToString converts an integer to string using loop-based conversion.
// No strconv allowed per requirements.
// Ported from: Standard integer to string conversion
//
// Algorithm:
//  1. Handle zero special case
//  2. Handle negative numbers
//  3. Extract digits in reverse order
//  4. Reverse the result
func intToString(num int) string {
	if num == 0 {
		return "0"
	}

	isNegative := false
	if num < 0 {
		isNegative = true
		num = -num
	}

	// Extract digits in reverse
	digits := make([]byte, 0, 12) // Max int is 10-11 digits
	for num > 0 {
		digit := num % 10
		digits = append(digits, byte('0'+digit))
		num = num / 10
	}

	// Add negative sign if needed
	if isNegative {
		digits = append(digits, '-')
	}

	// Reverse to get correct order
	length := len(digits)
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = digits[length-1-i]
	}

	return string(result)
}

// extractHeaderName extracts the name part of a header line.
// Returns everything before the first ':' character.
//
// Algorithm:
//  1. Find first ':' character
//  2. Return substring before it
//  3. If no ':', return entire string
func extractHeaderName(header string) string {
	for i := 0; i < len(header); i++ {
		if header[i] == ':' {
			return header[:i]
		}
	}
	return header
}

// trimSpace removes leading and trailing whitespace from a string.
func trimSpace(s string) string {
	// Find first non-space
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}

	// Find last non-space
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}

	return s[start:end]
}

// indexByte finds the first occurrence of a byte in a string.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
