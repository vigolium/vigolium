package httpmsg

// response_analyzer.go - HTTP response analysis ported from Burp Suite
// Ported from:
//   - burp/IResponseInfo.java (lines 5-17) - Response info interface
//   - burp/by4.java (lines 6-60) - IResponseInfo implementation
//   - burp/hkk.java (lines 6-70) - Response data structure
//   - burp/dn.java (lines 8-109) - Response parsing logic
//   - burp/fci.java (lines 15-280) - Cookie parsing
//   - burp/def.java (lines 9-312) - MIME type definitions
//   - burp/d4n.java (lines 204-215) - analyzeResponse entry point
//
// CRITICAL: Uses ONLY loop-based parsing (NO REGEX)
// Follows Burp's char-by-char parsing patterns

import (
	"time"
)

// ResponseInfo represents parsed HTTP response information.
// Ported from: IResponseInfo interface (burp/IResponseInfo.java lines 5-17)
//
//	by4.java implementation (lines 6-60)
//
// Maps to 6 getter methods in IResponseInfo:
//   - getStatusCode() -> StatusCode
//   - getHeaders() -> Headers
//   - getBodyOffset() -> BodyOffset
//   - getStatedMimeType() -> StatedMimeType
//   - getInferredMimeType() -> InferredMimeType
//   - getCookies() -> Cookies
type ResponseInfo struct {
	// StatusCode is the HTTP status code (short in Java)
	// Maps to IResponseInfo.getStatusCode() (IResponseInfo.java line 10)
	// Stored in hkk.a field (hkk.java line 11)
	StatusCode int16

	// Headers is the list of HTTP headers (including status line)
	// Maps to IResponseInfo.getHeaders() (IResponseInfo.java line 6)
	// Stored in hkk.l field (hkk.java line 8)
	Headers []string

	// BodyOffset is the byte offset where response body starts
	// Maps to IResponseInfo.getBodyOffset() (IResponseInfo.java line 8)
	// Stored in hkk.g field (hkk.java line 10)
	BodyOffset int

	// StatedMimeType is the MIME type from Content-Type header
	// Maps to IResponseInfo.getStatedMimeType() (IResponseInfo.java line 14)
	// Derived from hkk.c.e field (by4.java line 53)
	StatedMimeType string

	// InferredMimeType is the inferred MIME type from body content
	// Maps to IResponseInfo.getInferredMimeType() (IResponseInfo.java line 16)
	// Derived from hkk.c.g field (by4.java line 58)
	InferredMimeType string

	// Cookies is the list of parsed Set-Cookie headers
	// Maps to IResponseInfo.getCookies() (IResponseInfo.java line 12)
	// Stored in hkk.j field (hkk.java line 16)
	Cookies []*Cookie
}

// Cookie represents an HTTP cookie from Set-Cookie header.
// Ported from: burp/ICookie.java interface (lines 5-15)
//
//	burp/ap3.java implementation (cookie storage)
//	burp/fu_.java (lines 5-40) - ICookie wrapper
//
// Maps to 5 getter methods in ICookie:
//   - getName() -> Name
//   - getValue() -> Value
//   - getDomain() -> Domain
//   - getPath() -> Path
//   - getExpiration() -> Expiration
type Cookie struct {
	// Name is the cookie name
	// Maps to ICookie.getName() (ICookie.java line 12)
	Name string

	// Value is the cookie value
	// Maps to ICookie.getValue() (ICookie.java line 14)
	Value string

	// Domain is the domain attribute
	// Maps to ICookie.getDomain() (ICookie.java line 6)
	Domain string

	// Path is the path attribute
	// Maps to ICookie.getPath() (ICookie.java line 8)
	Path string

	// Expiration is the expires/max-age timestamp
	// Maps to ICookie.getExpiration() (ICookie.java line 10)
	// Returns nil if no expiration set
	Expiration *time.Time
}

// AnalyzeResponse analyzes an HTTP response and extracts structured information.
// Ported from: d4n.analyzeResponse(byte[] var1) (d4n.java lines 204-215)
//
//	dn.a(hik, bi9, h2, c5e) (dn.java lines 19-79)
//
// Algorithm (dn.java lines 19-79):
//  1. Find body offset using FindBodyOffset (line 24, calls glo.b)
//  2. Extract headers using ExtractAllHeaders (line 30, calls glo.a)
//  3. Parse status line for status code (lines 48-54)
//  4. Extract Content-Type for StatedMimeType (line 62, calls ea5.a)
//  5. Infer MIME type from response body (line 62, ea5.a infers type)
//  6. Parse all Set-Cookie headers into Cookie objects (line 72, calls fci.a)
//
// Parameters:
//   - response: Complete HTTP response bytes
//
// Returns:
//   - ResponseInfo with all fields populated
//   - Error if parsing fails
//
// Example:
//
//	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: id=123\r\n\r\n<html>")
//	info, _ := AnalyzeResponse(response)
//	// info.StatusCode = 200
//	// info.StatedMimeType = "text/html"
//	// info.Cookies[0].Name = "id", Value = "123"
func AnalyzeResponse(response []byte) (*ResponseInfo, error) {
	if response == nil {
		return nil, nil
	}

	info := &ResponseInfo{}

	// Step 1: Find body offset (dn.java lines 24-27)
	// Calls glo.b(var1, 0) which finds header/body separator
	bodyOffset := FindBodyOffset(response)
	info.BodyOffset = bodyOffset

	// Step 2: Extract headers (dn.java lines 29-31)
	// Calls glo.a(var1, 0, var8, var9, var4, var6)
	headers, _, _, _ := ExtractAllHeaders(response)
	info.Headers = headers

	// Step 3: Parse status code from status line (dn.java lines 48-54)
	// Uses StringTokenizer to parse "HTTP/1.1 200 OK"
	if len(headers) > 0 {
		info.StatusCode = parseStatusLine(headers[0])
	}

	// Step 4: Extract stated MIME type from Content-Type header
	// (dn.java line 62, calls ea5.a which parses Content-Type)
	// def.d(this.a.c.e) returns string from short type (by4.java line 53)
	contentType := Header(headers, "Content-Type")
	info.StatedMimeType = extractMimeType(contentType)

	// Step 5: Infer MIME type from response body
	// (dn.java line 62, ea5.a infers from body content)
	// def.d(this.a.c.g) returns string from short type (by4.java line 58)
	if bodyOffset < len(response) {
		body := response[bodyOffset:]
		info.InferredMimeType = inferMimeType(body)
	}

	// Step 6: Parse Set-Cookie headers (dn.java line 72)
	// Calls fci.a(var13, var10, var9) to parse cookies
	info.Cookies = parseSetCookieHeaders(headers)

	return info, nil
}

// parseStatusLine extracts HTTP status code from status line.
// Ported from: dn.java lines 48-54
//
// Algorithm (dn.java lines 48-54):
//  1. Use StringTokenizer on status line (line 48)
//  2. First token is HTTP version (line 49)
//  3. Second token is status code (line 50)
//  4. Parse as Short (line 50: Short.parseShort)
//  5. Handle exceptions (lines 55-57)
//
// Status line format: "HTTP/1.1 200 OK"
// Uses loop-based parsing (NO REGEX)
//
// Parameters:
//   - statusLine: First line of HTTP response
//
// Returns:
//   - Status code as int16 (short in Java)
//   - Returns 0 if parsing fails
//
// Example:
//
//	code := parseStatusLine("HTTP/1.1 200 OK")
//	// code = 200
func parseStatusLine(statusLine string) int16 {
	if statusLine == "" {
		return 0
	}

	// Parse tokens separated by spaces
	// Equivalent to StringTokenizer in Java (dn.java line 48)
	tokens := parseTokens(statusLine, ' ')

	// Need at least 2 tokens: "HTTP/1.1" and "200"
	// (dn.java lines 49-50)
	if len(tokens) < 2 {
		return 0
	}

	// Second token is status code (dn.java line 50)
	statusCodeStr := tokens[1]

	// Parse as short (dn.java line 50: Short.parseShort)
	// Loop-based integer parsing (no strconv)
	statusCode := parseShort(statusCodeStr)

	return statusCode
}

// parseSetCookieHeaders parses all Set-Cookie headers into Cookie objects.
// Ported from: fci.a(fs7, List<String>, List<Integer>) (fci.java lines 19-106)
//
// Algorithm (fci.java lines 19-106):
//  1. Loop through all headers (line 27)
//  2. Find Set-Cookie headers (line 30, case-insensitive check)
//  3. Parse cookie name=value (lines 38-40, calls b())
//  4. Parse cookie attributes: Domain, Path, Expires (lines 42-94)
//  5. Create Cookie object for each Set-Cookie (line 96)
//
// Parameters:
//   - headers: List of HTTP headers
//
// Returns:
//   - List of parsed Cookie objects
//
// Example:
//
//	headers := []string{"HTTP/1.1 200 OK", "Set-Cookie: id=123; Domain=.example.com; Path=/"}
//	cookies := parseSetCookieHeaders(headers)
//	// cookies[0].Name = "id", Value = "123", Domain = ".example.com"
func parseSetCookieHeaders(headers []string) []*Cookie {
	var cookies []*Cookie

	// Loop through headers looking for Set-Cookie (fci.java line 27)
	for _, header := range headers {
		// Check if this is a Set-Cookie header (fci.java line 30)
		// Case-insensitive comparison: toLowerCase().startsWith("set-cookie:")
		if len(header) >= 11 && startsWithCaseInsensitive(header, "set-cookie:") {
			// Parse this Set-Cookie header
			cookie := parseSetCookie(header)
			if cookie != nil {
				cookies = append(cookies, cookie)
			}
		}
	}

	return cookies
}

// parseSetCookie parses a single Set-Cookie header value into a Cookie object.
// Ported from: fci.java lines 38-96 (parsing logic within loop)
//
//	fci.b(String) (lines 141-163) - extract name/value
//
// Algorithm (fci.java lines 38-96):
//  1. Extract cookie name=value before first semicolon (lines 38-40, calls b())
//  2. Loop through attributes after semicolons (lines 42-94)
//  3. Parse Domain attribute (lines 66-90)
//  4. Parse Expires attribute (lines 91-93, calls a(String))
//  5. Parse Path attribute (implicit in attribute parsing)
//
// Set-Cookie format: "name=value; Domain=.example.com; Path=/; Expires=..."
// Uses loop-based parsing (NO REGEX)
//
// Parameters:
//   - setCookieValue: Complete Set-Cookie header line
//
// Returns:
//   - Parsed Cookie object, or nil if parsing fails
//
// Example:
//
//	cookie := parseSetCookie("Set-Cookie: id=123; Domain=.example.com; Path=/")
//	// cookie.Name = "id", Value = "123", Domain = "example.com", Path = "/"
func parseSetCookie(setCookieValue string) *Cookie {
	if len(setCookieValue) < 11 {
		return nil
	}

	// Skip "Set-Cookie:" prefix (11 characters)
	value := setCookieValue[11:]

	// Extract cookie name=value before first semicolon
	// (fci.java lines 38-40, calls b(var6))
	// b() is defined at lines 141-163
	name, cookieValue, remaining := extractCookieNameValue(value)
	if name == "" {
		return nil
	}

	cookie := &Cookie{
		Name:  name,
		Value: cookieValue,
	}

	// Parse attributes after semicolons (fci.java lines 42-94)
	parsePosition := 0
	for parsePosition < len(remaining) {
		// Find next attribute (between semicolons)
		attrStart := parsePosition

		// Skip leading whitespace and semicolons
		for attrStart < len(remaining) && (remaining[attrStart] == ' ' || remaining[attrStart] == ';') {
			attrStart++
		}
		if attrStart >= len(remaining) {
			break
		}

		// Find end of attribute name (before '=' or ';')
		attrNameEnd := attrStart
		for attrNameEnd < len(remaining) && remaining[attrNameEnd] != '=' && remaining[attrNameEnd] != ';' {
			attrNameEnd++
		}

		attrName := TrimSpace(remaining[attrStart:attrNameEnd])

		// Check if there's a value (after '=')
		attrValueStart := attrNameEnd
		attrValueEnd := attrNameEnd

		if attrNameEnd < len(remaining) && remaining[attrNameEnd] == '=' {
			attrValueStart = attrNameEnd + 1

			// Find end of attribute value (before next ';')
			attrValueEnd = attrValueStart
			for attrValueEnd < len(remaining) && remaining[attrValueEnd] != ';' {
				attrValueEnd++
			}
		}

		attrValue := ""
		if attrValueStart < len(remaining) {
			attrValue = TrimSpace(remaining[attrValueStart:attrValueEnd])
		}

		// Parse specific attributes (fci.java lines 66-93)

		// Domain attribute (fci.java lines 66-90)
		if EqualsCaseInsensitive(attrName, "domain") {
			// Remove leading dots and wildcards (fci.java lines 79-82)
			domain := attrValue
			for len(domain) > 0 && (domain[0] == '.' || domain[0] == '*') {
				domain = domain[1:]
			}
			cookie.Domain = domain
		}

		// Path attribute (implicit in fci.java attribute parsing)
		if EqualsCaseInsensitive(attrName, "path") {
			cookie.Path = attrValue
		}

		// Expires attribute (fci.java lines 91-93)
		if EqualsCaseInsensitive(attrName, "expires") {
			expiration := parseExpirationDate(attrValue)
			cookie.Expiration = expiration
		}

		// Max-Age attribute (takes precedence over Expires)
		if EqualsCaseInsensitive(attrName, "max-age") {
			maxAge := parseInt(attrValue)
			if maxAge > 0 {
				expTime := time.Now().Add(time.Duration(maxAge) * time.Second)
				cookie.Expiration = &expTime
			}
		}

		// Move to next attribute
		parsePosition = attrValueEnd
		if parsePosition < len(remaining) && remaining[parsePosition] == ';' {
			parsePosition++
		}
	}

	return cookie
}

// extractCookieNameValue extracts cookie name and value from Set-Cookie header.
// Ported from: fci.b(String var0) (fci.java lines 141-163)
//
// Algorithm (fci.java lines 141-163):
//  1. Find first semicolon (line 142)
//  2. Extract substring before semicolon (line 144)
//  3. Find equals sign (line 151)
//  4. Extract name (substring 11 to equals) (line 160)
//  5. Extract value (substring after equals) (line 161)
//  6. Return e8t object with name, value, offsets (line 162)
//
// Parameters:
//   - value: Set-Cookie value after "Set-Cookie:" prefix
//
// Returns:
//   - name: Cookie name
//   - cookieValue: Cookie value
//   - remaining: Remaining string after name=value (for attributes)
//
// Example:
//
//	name, value, remaining := extractCookieNameValue(" id=123; Domain=.example.com")
//	// name = "id", value = "123", remaining = "; Domain=.example.com"
func extractCookieNameValue(value string) (name, cookieValue, remaining string) {
	// Find first semicolon (fci.java line 142)
	semiIdx := FindCharIndex(value, SEMI)

	nameValuePart := value
	remaining = ""

	if semiIdx != -1 {
		// Extract part before semicolon (fci.java line 144)
		nameValuePart = value[0:semiIdx]
		remaining = value[semiIdx:]
	}

	// Find equals sign (fci.java line 151)
	equalsIdx := FindCharIndex(nameValuePart, EQ)

	if equalsIdx == -1 {
		// No equals sign, treat entire part as name (fci.java lines 154-157)
		name = TrimSpace(nameValuePart)
		cookieValue = ""
		return
	}

	// Extract name and value (fci.java lines 160-161)
	name = TrimSpace(nameValuePart[0:equalsIdx])
	cookieValue = TrimSpace(nameValuePart[equalsIdx+1:])

	return
}

// parseExpirationDate parses cookie expiration date string.
// Ported from: fci.a(String var0) (fci.java lines 108-121)
//
// Algorithm (fci.java lines 108-121):
//  1. Try multiple date formats (line 110, iterates over c[] array)
//  2. Use SimpleDateFormat.parse for each format (line 112)
//  3. Return first successful parse (line 113)
//  4. Return nil if all formats fail (line 120)
//
// Supported formats (fci.java line 16):
//   - "EEE, d-MMM-yyyy HH:mm:ss Z"  (e.g., "Mon, 01-Jan-2024 00:00:00 GMT")
//   - "EEE, d MMM yyyy HH:mm:ss Z"  (e.g., "Mon, 01 Jan 2024 00:00:00 GMT")
//
// Parameters:
//   - dateStr: Date string from Expires attribute
//
// Returns:
//   - Parsed time, or nil if parsing fails
//
// Example:
//
//	t := parseExpirationDate("Mon, 01-Jan-2024 00:00:00 GMT")
//	// t is parsed time.Time for Jan 1, 2024
func parseExpirationDate(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	// Try common cookie date formats (fci.java lines 110-117)
	// Formats from fci.java line 16
	formats := []string{
		"Mon, 02-Jan-2006 15:04:05 MST",
		"Mon, 02 Jan 2006 15:04:05 MST",
		"Monday, 02-Jan-06 15:04:05 MST",
		"Monday, 02 Jan 06 15:04:05 MST",
		"Mon, 2-Jan-2006 15:04:05 MST",
		"Mon, 2 Jan 2006 15:04:05 MST",
	}

	for _, format := range formats {
		t, err := time.Parse(format, dateStr)
		if err == nil {
			// Adjust 2-digit years (fci.java lines 123-138)
			// If year < 100, adjust to 1900s or 2000s
			year := t.Year()
			if year < 100 {
				if year < 70 {
					t = t.AddDate(2000-year, 0, 0)
				} else {
					t = t.AddDate(1900-year, 0, 0)
				}
			}
			return &t
		}
	}

	// All formats failed (fci.java line 120)
	return nil
}

// inferMimeType infers MIME type from response body content.
// Ported from: ea5.a (MIME type inference logic)
//
//	def.d(short) (def.java lines 190-242) - Convert type to string
//
// Algorithm:
//  1. Check first few bytes for common patterns
//  2. HTML: Check for <html, <!DOCTYPE, <body, <head tags
//  3. JSON: Check for leading { or [
//  4. XML: Check for <?xml or < prefix
//  5. Return corresponding MIME type string
//
// MIME type constants (def.java lines 136-242):
//   - 256 = "HTML"
//   - 260 = "JSON"
//   - 262 = "XML"
//   - 257 = "text"
//
// Uses loop-based pattern matching (NO REGEX)
//
// Parameters:
//   - body: Response body bytes
//
// Returns:
//   - Inferred MIME type string (e.g., "HTML", "JSON", "XML")
//
// Example:
//
//	mimeType := inferMimeType([]byte("<html><body>"))
//	// mimeType = "HTML"
func inferMimeType(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	// Skip leading whitespace
	start := 0
	for start < len(body) && isWhitespaceByte(body[start]) {
		start++
	}

	if start >= len(body) {
		return ""
	}

	// Check for HTML patterns
	// def.java line 199: case 256 returns "HTML"
	if hasPrefix(body[start:], []byte("<html")) ||
		hasPrefix(body[start:], []byte("<HTML")) ||
		hasPrefix(body[start:], []byte("<!DOCTYPE")) ||
		hasPrefix(body[start:], []byte("<!doctype")) ||
		hasPrefix(body[start:], []byte("<body")) ||
		hasPrefix(body[start:], []byte("<BODY")) ||
		hasPrefix(body[start:], []byte("<head")) ||
		hasPrefix(body[start:], []byte("<HEAD")) {
		return "HTML"
	}

	// Check for JSON patterns
	// def.java line 207: case 260 returns "JSON"
	if body[start] == '{' || body[start] == '[' {
		return "JSON"
	}

	// Check for XML patterns
	// def.java line 212: case 262 returns "XML"
	if hasPrefix(body[start:], []byte("<?xml")) ||
		hasPrefix(body[start:], []byte("<?XML")) {
		return "XML"
	}

	// Check for generic XML tag
	if body[start] == '<' {
		return "XML"
	}

	// Default to empty (def.java line 193: case 0 returns "")
	return ""
}

// extractMimeType extracts MIME type from Content-Type header value.
// Helper function to get the MIME type part before semicolon.
//
// Parameters:
//   - contentType: Content-Type header value
//
// Returns:
//   - MIME type string (e.g., "text/html")
//
// Example:
//
//	mimeType := extractMimeType("text/html; charset=utf-8")
//	// mimeType = "text/html"
func extractMimeType(contentType string) string {
	if contentType == "" {
		return ""
	}

	// Find semicolon (before parameters)
	semiIdx := FindCharIndex(contentType, SEMI)

	if semiIdx == -1 {
		// No parameters, return trimmed content type
		return TrimSpace(contentType)
	}

	// Return part before semicolon
	return TrimSpace(contentType[0:semiIdx])
}

// Helper functions

// parseTokens splits string by delimiter into tokens.
// Equivalent to Java's StringTokenizer (used in dn.java line 48).
// Loop-based implementation (NO strings.Split).
//
// Parameters:
//   - s: String to tokenize
//   - delimiter: Delimiter character
//
// Returns:
//   - List of tokens
func parseTokens(s string, delimiter byte) []string {
	var tokens []string
	tokenStart := 0

	for i := 0; i < len(s); i++ {
		if s[i] == delimiter {
			// Found delimiter, extract token
			if i > tokenStart {
				token := s[tokenStart:i]
				tokens = append(tokens, token)
			}
			tokenStart = i + 1
		}
	}

	// Add final token
	if tokenStart < len(s) {
		token := s[tokenStart:]
		tokens = append(tokens, token)
	}

	return tokens
}

// parseShort parses string to int16 (short in Java).
// Loop-based integer parsing (NO strconv).
//
// Parameters:
//   - s: String to parse
//
// Returns:
//   - Parsed int16 value, or 0 if invalid
func parseShort(s string) int16 {
	if s == "" {
		return 0
	}

	// Handle negative numbers
	negative := false
	start := 0
	if s[0] == '-' {
		negative = true
		start = 1
	}

	// Parse digits
	var result int16 = 0
	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			// Invalid character
			return 0
		}
		digit := int16(s[i] - '0')
		result = result*10 + digit
	}

	if negative {
		result = -result
	}

	return result
}

// parseInt parses string to int.
// Loop-based integer parsing (NO strconv).
//
// Parameters:
//   - s: String to parse
//
// Returns:
//   - Parsed int value, or 0 if invalid
func parseInt(s string) int {
	if s == "" {
		return 0
	}

	// Handle negative numbers
	negative := false
	start := 0
	if s[0] == '-' {
		negative = true
		start = 1
	}

	// Parse digits
	result := 0
	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			// Invalid character
			return 0
		}
		digit := int(s[i] - '0')
		result = result*10 + digit
	}

	if negative {
		result = -result
	}

	return result
}

// startsWithCaseInsensitive checks if string starts with prefix (case-insensitive).
// Loop-based implementation.
//
// Parameters:
//   - s: String to check
//   - prefix: Prefix to match
//
// Returns:
//   - true if s starts with prefix (case-insensitive)
func startsWithCaseInsensitive(s, prefix string) bool {
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

// hasPrefix checks if byte slice has given prefix.
// Loop-based byte-by-byte comparison.
//
// Parameters:
//   - data: Byte slice to check
//   - prefix: Prefix bytes to match
//
// Returns:
//   - true if data starts with prefix
func hasPrefix(data, prefix []byte) bool {
	if len(data) < len(prefix) {
		return false
	}

	for i := 0; i < len(prefix); i++ {
		if data[i] != prefix[i] {
			return false
		}
	}

	return true
}

// isWhitespaceByte checks if byte is whitespace.
// Checks for space, tab, CR, LF.
//
// Parameters:
//   - b: Byte to check
//
// Returns:
//   - true if whitespace
func isWhitespaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// ==================== RESPONSE/REQUEST DETECTION ====================

// IsResponse checks if message is an HTTP response (starts with "HTTP/").
// Ported from: Utilities.java isResponse() (lines 976-979)
//
// Algorithm:
//  1. Check if message starts with "HTTP/" (case-insensitive)
//  2. Return true if it does
//
// Parameters:
//   - message: HTTP message bytes
//
// Returns:
//   - true if message is an HTTP response
//
// Example:
//
//	isResp := IsResponse(data)  // "HTTP/1.1 200 OK..." → true
//	isResp := IsResponse(data)  // "GET / HTTP/1.1..." → false
func IsResponse(message []byte) bool {
	if len(message) < 5 {
		return false
	}

	// Check for "HTTP/" prefix (case-insensitive)
	return (message[0] == 'H' || message[0] == 'h') &&
		(message[1] == 'T' || message[1] == 't') &&
		(message[2] == 'T' || message[2] == 't') &&
		(message[3] == 'P' || message[3] == 'p') &&
		message[4] == '/'
}

// IsRequest checks if message is an HTTP request (not a response).
// Complement of IsResponse.
//
// Parameters:
//   - message: HTTP message bytes
//
// Returns:
//   - true if message is an HTTP request
//
// Example:
//
//	isReq := IsRequest(data)  // "GET / HTTP/1.1..." → true
//	isReq := IsRequest(data)  // "HTTP/1.1 200 OK..." → false
func IsRequest(message []byte) bool {
	if len(message) == 0 {
		return false
	}
	return !IsResponse(message)
}

// GetStatusCode extracts status code from response (shortcut for AnalyzeResponse).
// Ported from: Utilities.java getCode() (lines 813-833)
//
// Algorithm:
//  1. Find first space (after HTTP version)
//  2. Find second space (after status code)
//  3. Parse status code between the two spaces
//
// Parameters:
//   - response: HTTP response bytes
//
// Returns:
//   - Status code as int16 (e.g., 200, 404, 500)
//   - Returns 0 if not a valid response
//
// Example:
//
//	code := GetStatusCode(response)  // "HTTP/1.1 404 Not Found" → 404
func GetStatusCode(response []byte) int16 {
	if len(response) < 12 {
		return 0
	}

	// Find first space (after HTTP version)
	firstSpace := -1
	for i := 0; i < len(response) && i < 20; i++ {
		if response[i] == ' ' {
			firstSpace = i
			break
		}
	}

	if firstSpace == -1 || firstSpace+4 > len(response) {
		return 0
	}

	// Find second space or line end (after status code)
	secondSpace := -1
	for i := firstSpace + 1; i < len(response) && i < firstSpace+5; i++ {
		if response[i] == ' ' || response[i] == CR || response[i] == LF {
			secondSpace = i
			break
		}
	}

	if secondSpace == -1 {
		secondSpace = firstSpace + 4 // Assume 3-digit code
		if secondSpace > len(response) {
			return 0
		}
	}

	// Parse status code
	codeStr := string(response[firstSpace+1 : secondSpace])
	return parseShort(codeStr)
}

// GetStartType detects content type from response body start.
// Ported from: Utilities.java getStartType() (lines 768-786)
//
// Algorithm:
//  1. Find body offset
//  2. Skip leading whitespace
//  3. Check for known content patterns
//  4. Return type identifier
//
// Parameters:
//   - response: HTTP response bytes
//
// Returns:
//   - Content type string: "[blank]", "<html", "<head", "text", etc.
//
// Example:
//
//	startType := GetStartType(response)  // "<html>..." → "<html"
//	startType := GetStartType(response)  // "{..." → "json"
func GetStartType(response []byte) string {
	if response == nil {
		return "[blank]"
	}

	// Find body offset
	bodyOffset := FindBodyOffset(response)
	if bodyOffset >= len(response) {
		return "[blank]"
	}

	body := response[bodyOffset:]
	if len(body) == 0 {
		return "[blank]"
	}

	// Skip leading whitespace
	start := 0
	for start < len(body) && isWhitespaceByte(body[start]) {
		start++
	}

	if start >= len(body) {
		return "[blank]"
	}

	// Check for known patterns
	remaining := body[start:]

	// HTML patterns
	if len(remaining) >= 5 && hasPrefix(remaining, []byte("<html")) {
		return "<html"
	}
	if len(remaining) >= 5 && hasPrefix(remaining, []byte("<HTML")) {
		return "<html"
	}
	if len(remaining) >= 5 && hasPrefix(remaining, []byte("<head")) {
		return "<head"
	}
	if len(remaining) >= 5 && hasPrefix(remaining, []byte("<HEAD")) {
		return "<head"
	}
	if len(remaining) >= 5 && hasPrefix(remaining, []byte("<body")) {
		return "<body"
	}
	if len(remaining) >= 5 && hasPrefix(remaining, []byte("<BODY")) {
		return "<body"
	}
	if len(remaining) >= 9 && hasPrefix(remaining, []byte("<!DOCTYPE")) {
		return "<!DOCTYPE"
	}
	if len(remaining) >= 9 && hasPrefix(remaining, []byte("<!doctype")) {
		return "<!DOCTYPE"
	}

	// JSON patterns
	if remaining[0] == '{' || remaining[0] == '[' {
		return "json"
	}

	// XML patterns
	if len(remaining) >= 5 && hasPrefix(remaining, []byte("<?xml")) {
		return "<?xml"
	}
	// HTML comment — treat as HTML (e.g. pages starting with license comments)
	if len(remaining) >= 4 && hasPrefix(remaining, []byte("<!--")) {
		return "<!--"
	}
	if remaining[0] == '<' {
		return "xml"
	}

	// Default to text
	return "text"
}

// GetNestedResponse extracts nested HTTP response from body.
// Ported from: Utilities.java getNestedResponse() (lines 1137-1144)
// Useful for HTTP request smuggling detection.
//
// Algorithm:
//  1. Find body offset of outer response
//  2. Search for "HTTP/" in body (start of nested response)
//  3. Return nested response bytes
//
// Parameters:
//   - response: HTTP response bytes
//
// Returns:
//   - Nested response bytes, or nil if not found
//
// Example:
//
//	nested := GetNestedResponse(response)
//	// If body contains "HTTP/1.1 200 OK...", returns that response
func GetNestedResponse(response []byte) []byte {
	if response == nil {
		return nil
	}

	// Find body offset
	bodyOffset := FindBodyOffset(response)
	if bodyOffset >= len(response) {
		return nil
	}

	body := response[bodyOffset:]

	// Search for HTTP response in body
	for i := 0; i <= len(body)-5; i++ {
		if (body[i] == 'H' || body[i] == 'h') &&
			(body[i+1] == 'T' || body[i+1] == 't') &&
			(body[i+2] == 'T' || body[i+2] == 't') &&
			(body[i+3] == 'P' || body[i+3] == 'p') &&
			body[i+4] == '/' {
			// Found nested response
			return body[i:]
		}
	}

	return nil
}
