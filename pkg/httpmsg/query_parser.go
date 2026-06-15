package httpmsg

// query_parser.go - Query string parameter parsing

// ParseQueryString extracts query string parameters from a URL byte array.
// This function parses URL query parameters in the format: ?key1=value1&key2=value2
//
// Algorithm:
//  1. Find query string boundaries (after '?' and before '#' or end)
//  2. Loop through query string character by character
//  3. Parse each parameter as name=value pair separated by '&'
//  4. Handle edge cases: empty values, no values, trailing separators
//  5. Track byte offsets for name and value positions
//
// Example:
//
//	url := []byte("http://example.com/path?foo=bar&name=John%20Doe&flag")
//	params, err := ParseQueryString(url)
//	// Returns:
//	//   [0] = {Type: ParamURL, Name: "foo", Value: "bar", NameStart: 28, NameEnd: 31, ValueStart: 32, ValueEnd: 35}
//	//   [1] = {Type: ParamURL, Name: "name", Value: "John%20Doe", NameStart: 36, NameEnd: 40, ValueStart: 41, ValueEnd: 51}
//	//   [2] = {Type: ParamURL, Name: "flag", Value: "", NameStart: 52, NameEnd: 56, ValueStart: 56, ValueEnd: 56}
//
// Parameters:
//   - url: Complete URL as byte array
//
// Returns:
//   - List of Param objects with ParamURL type
//   - Error if parsing fails (currently never returns error for compatibility)
func ParseQueryString(url []byte) ([]*Param, error) {
	if url == nil {
		return []*Param{}, nil
	}

	// Find query string boundaries
	queryBounds := findQueryBounds(url)
	if queryBounds == nil {
		return []*Param{}, nil
	}

	// Extract start and end positions of query string
	// queryBounds[0] is the position of '?', so we start from queryBounds[0] + 1
	// queryBounds[1] is the end position (before '#' or end of URL)
	queryStart := queryBounds[0] + 1
	queryEnd := queryBounds[1]

	// Parse parameters from query string range
	params := parseURLEncodedParameters(ParamURL, url, queryStart, queryEnd)

	return params, nil
}

// ParseQueryParameters parses URL-encoded parameters from a query string portion.
// Takes JUST the query parameters WITHOUT '?' (e.g., "id=123&name=test").
// For full URLs with '?', use ParseQueryString instead.
//
// This is the low-level parameter parsing API where the caller has already
// identified the query portion and passes it directly for parsing.
//
// Algorithm:
//  1. Validate input
//  2. Call parseURLEncodedParameters directly on entire input
//  3. No boundary detection (no '?' search) - input is already the query portion
//
// Parameters:
//   - queryString: Query parameters WITHOUT '?' prefix
//
// Returns:
//   - List of Param objects with ParamURL type
//
// Example:
//
//	queryString := []byte("id=123&name=test")  // No '?' prefix
//	params := ParseQueryParameters(queryString)
//	// Returns: [{Name: "id", Value: "123"}, {Name: "name", Value: "test"}]
func ParseQueryParameters(queryString []byte) []*Param {
	if len(queryString) == 0 {
		return []*Param{}
	}

	// Call low-level parser directly (no boundary detection needed)
	return parseURLEncodedParameters(ParamURL, queryString, 0, len(queryString))
}

// ExtractQueryParameters extracts query parameters from a URL within an HTTP request.
// The HTTP request format is: "GET /path?key=value HTTP/1.1\r\n..."
//
// Algorithm:
//  1. Extract URL portion from HTTP request (between method and HTTP version)
//  2. Find query string boundaries within the URL
//  3. Parse parameters using parseURLEncodedParameters
//  4. Adjust offsets to be relative to full request (not just URL)
//
// Example:
//
//	request := []byte("GET /path?foo=bar&name=value HTTP/1.1\r\nHost: example.com\r\n\r\n")
//	params, err := ExtractQueryParameters(request, 0, len(request))
//	// Returns parameters with offsets relative to the full request
//
// Parameters:
//   - request: Full HTTP request bytes
//   - urlStart: Start position of URL in request
//   - urlEnd: End position of URL in request
//
// Returns:
//   - List of Param objects with ParamURL type
//   - Error if parsing fails
func ExtractQueryParameters(request []byte, urlStart, urlEnd int) ([]*Param, error) {
	if request == nil || urlStart < 0 || urlEnd > len(request) || urlStart >= urlEnd {
		return []*Param{}, nil
	}

	// Extract URL portion from request
	url := SliceBytes(request, urlStart, urlEnd)

	// Find query string boundaries
	queryBounds := findQueryBounds(url)
	if queryBounds == nil {
		return []*Param{}, nil
	}

	// Parse parameters (offsets relative to url slice)
	queryStart := queryBounds[0] + 1
	queryEnd := queryBounds[1]
	parsedParams := parseURLEncodedParameters(ParamURL, url, queryStart, queryEnd)

	// Adjust offsets to be relative to full request
	params := make([]*Param, len(parsedParams))
	for i, param := range parsedParams {
		params[i] = param.WithAdjustedOffsets(urlStart)
	}

	return params, nil
}

// findQueryBounds finds the start and end positions of the query string in a URL.
// Returns [startPos, endPos] where startPos is the position of '?' and endPos is before '#' or end.
//
// Algorithm:
//  1. Loop through URL byte by byte
//  2. Return nil if newline (10) or fragment (#/35) found before '?'
//  3. When '?' (63) found, mark start position
//  4. Continue to find end (whitespace <=32 or fragment #/35)
//  5. Return [start, end] array
//
// Example:
//
//	url := []byte("http://example.com/path?foo=bar#anchor")
//	bounds := findQueryBounds(url)
//	// Returns [23, 31] where url[23] = '?' and url[31] = '#'
//
// Parameters:
//   - url: URL byte array
//
// Returns:
//   - [2]int with [startPos, endPos], or nil if no query string
func findQueryBounds(url []byte) []int {
	if url == nil {
		return nil
	}

	length := len(url)

	// Loop through URL to find '?'
	for i := 0; i < length; i++ {
		b := url[i]

		// Check for newline - invalid URL
		if b == 10 {
			return nil
		}

		// Check for fragment before query string
		if b == 35 { // '#' character
			return nil
		}

		// Check for '?' - start of query string
		if b == 63 { // '?' character
			queryStart := i
			i++ // Move past '?'

			// Find end of query string
			for i < length {
				b := url[i]
				// End conditions: whitespace (<=32) or fragment (#/35)
				if b <= 32 || b == 35 {
					return []int{queryStart, i}
				}
				i++
			}

			// Reached end of URL without finding terminator
			return []int{queryStart, length}
		}
	}

	// No query string found
	return nil
}

// parseURLEncodedParameters parses URL-encoded parameters from a byte range.
// This is the core parameter parsing logic for URL-encoded key=value pairs.
//
// Algorithm:
//  1. Initialize position markers: pos, nameStart, nameEnd, valueStart, valueEnd
//  2. Loop through byte range character by character
//  3. Skip leading CRLF/LF at parameter start
//  4. Find '=' character to separate name from value
//  5. Find '&' character to separate parameters
//  6. Handle edge cases: whitespace/control characters
//  7. Parse value portion after '='
//  8. Create Param object with offsets
//  9. Move to next parameter
//
// Example:
//
//	data := []byte("foo=bar&name=John&flag&trailing=")
//	params := parseURLEncodedParameters(ParamURL, data, 0, len(data))
//	// Returns 4 parameters: foo=bar, name=John, flag=(empty), trailing=(empty)
//
// Parameters:
//   - paramType: Type of parameters to create (ParamURL or ParamBody)
//   - data: Byte array containing parameters
//   - start: Start position in byte array
//   - end: End position in byte array
//
// Returns:
//   - List of Param objects with offsets
func parseURLEncodedParameters(paramType ParamType, data []byte, start, end int) []*Param {
	if data == nil || start < 0 || end > len(data) || start >= end {
		return []*Param{}
	}

	params := []*Param{}
	pos := start

	// Main parsing loop
	for pos < end {
		// Variables for tracking positions
		nameStart := pos
		nameEnd := -1
		valueStart := -1
		valueEnd := -1
		isAmpersandOnly := false // true if we hit '&' without finding '='

		// Skip leading newlines at start of parameter
		for nameStart == pos && pos < end {
			if data[pos] == 10 || data[pos] == 13 { // LF or CR
				nameStart++
				pos++
				continue
			}
			break
		}

		// Find '=' or '&' to determine name boundary
		for pos < end {
			b := data[pos]

			// Found '=' separator between name and value
			if b == 61 { // '=' character
				nameEnd = pos
				break
			}

			// Found '&' separator - parameter with no value
			if b == 38 { // '&' character
				isAmpersandOnly = true
				nameEnd = pos
				valueStart = pos
				valueEnd = pos
				break
			}

			// Control character or whitespace - end of parameters
			if b < 32 {
				break
			}

			pos++
		}

		// If we didn't find '=' or '&', set boundaries to current position
		if nameEnd == -1 {
			nameEnd = pos
			valueStart = pos
			valueEnd = pos
		} else if !isAmpersandOnly {
			// Found '=' - parse value portion
			valueStart = pos + 1 // Skip '=' character
			valueEnd = -1
			pos++ // Move past '='

			// Find end of value - look for '&' or control character
			for pos < end {
				b := data[pos]
				// Found '&' or control character - end of value
				if b == 38 || b < 32 { // '&' or control char
					valueEnd = pos
					break
				}
				pos++
			}

			// If no terminator found, value extends to end
			if valueEnd == -1 {
				valueEnd = end
			}
		}

		// Create parameter if valid name found
		if nameEnd > nameStart {
			name := DecodeQueryValue(string(data[nameStart:nameEnd]))
			value := DecodeQueryValue(string(data[valueStart:valueEnd]))

			param := NewParsedParam(
				paramType,
				name,
				value,
				nameStart,
				nameEnd,
				valueStart,
				valueEnd,
			)
			params = append(params, param)
		}

		// Move to next parameter
		pos = valueEnd + 1
	}

	return params
}

// FindQueryStart finds the position of the '?' character in a URL.
// Uses simple loop-based search (NO REGEX per requirements).
// Note: For full query string bounds detection, use findQueryBounds instead.
//
// Algorithm:
//  1. Loop through byte array
//  2. Return position when '?' (63) found
//  3. Return -1 if not found
//
// Example:
//
//	url := []byte("http://example.com/path?foo=bar")
//	pos := FindQueryStart(url)
//	// Returns 23 (position of '?')
//
// Parameters:
//   - url: URL byte array
//
// Returns:
//   - Position of '?' character, or -1 if not found
func FindQueryStart(url []byte) int {
	if url == nil {
		return -1
	}

	// Loop-based search for '?' (63)
	for i := 0; i < len(url); i++ {
		if url[i] == 63 { // '?' character
			return i
		}
	}

	return -1
}

// DecodeQueryValue decodes URL-encoded value using loop-based parsing.
// Handles %XX hex sequences and '+' to space conversion.
// NO REGEX, NO url.QueryUnescape per requirements.
//
// Algorithm:
//  1. Loop through string character by character
//  2. When '%' found, decode next 2 hex characters
//  3. When '+' found, convert to space
//  4. Otherwise, copy character as-is
//
// Example:
//
//	encoded := "John%20Doe+Smith"
//	decoded := DecodeQueryValue(encoded)
//	// Returns "John Doe Smith"
//
//	encoded := "hello%2Bworld"
//	decoded := DecodeQueryValue(encoded)
//	// Returns "hello+world"
//
// Parameters:
//   - encoded: URL-encoded string
//
// Returns:
//   - Decoded string
func DecodeQueryValue(encoded string) string {
	if encoded == "" {
		return ""
	}

	result := make([]byte, 0, len(encoded))

	// Loop through string character by character
	for i := 0; i < len(encoded); i++ {
		ch := encoded[i]

		// Handle '%XX' hex encoding
		if ch == '%' && i+2 < len(encoded) {
			hex1 := HexCharToValue(encoded[i+1])
			hex2 := HexCharToValue(encoded[i+2])

			if hex1 != -1 && hex2 != -1 {
				// Valid hex sequence - decode it
				result = append(result, byte(hex1*16+hex2))
				i += 2 // Skip the 2 hex characters
				continue
			}
			// Invalid hex sequence - treat '%' as literal
		}

		// Handle '+' to space conversion (URL query string specific)
		if ch == '+' {
			result = append(result, ' ')
			continue
		}

		// Regular character - copy as-is
		result = append(result, ch)
	}

	return string(result)
}

// HexCharToValue converts a hexadecimal character to its numeric value.
// Uses switch/case logic (NO REGEX per requirements).
//
// Algorithm:
//  1. Check if character is '0'-'9': return value 0-9
//  2. Check if character is 'a'-'f': return value 10-15
//  3. Check if character is 'A'-'F': return value 10-15
//  4. Otherwise return -1 (invalid hex)
//
// Example:
//
//	HexCharToValue('3')  // Returns 3
//	HexCharToValue('A')  // Returns 10
//	HexCharToValue('f')  // Returns 15
//	HexCharToValue('G')  // Returns -1 (invalid)
//
// Parameters:
//   - ch: Character to convert
//
// Returns:
//   - Numeric value (0-15), or -1 if invalid hex character
func HexCharToValue(ch byte) int {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0')
	case ch >= 'a' && ch <= 'f':
		return int(ch - 'a' + 10)
	case ch >= 'A' && ch <= 'F':
		return int(ch - 'A' + 10)
	default:
		return -1
	}
}

// EncodeQueryValue encodes a string for safe use in URL query parameters.
// Uses loop-based encoding (NO REGEX, NO url.QueryEscape per requirements).
//
// Algorithm:
//  1. Loop through string byte by byte
//  2. Encode unreserved characters as-is: A-Z, a-z, 0-9, -, _, ., ~
//  3. Encode space as '+'
//  4. Encode everything else as %XX hex sequence
//
// Example:
//
//	EncodeQueryValue("John Doe")      // Returns "John+Doe"
//	EncodeQueryValue("hello+world")   // Returns "hello%2Bworld"
//	EncodeQueryValue("a=b&c=d")       // Returns "a%3Db%26c%3Dd"
//
// Parameters:
//   - decoded: String to encode
//
// Returns:
//   - URL-encoded string
func EncodeQueryValue(decoded string) string {
	if decoded == "" {
		return ""
	}
	return string(appendQueryEncoded(make([]byte, 0, len(decoded)+8), decoded))
}

// EncodeQueryValueBytes is the []byte-native form of EncodeQueryValue. It avoids
// the []byte→string→[]byte round trips the string form forces on the
// insertion-point fuzzing hot path (encodePayload). Returns nil for empty input.
func EncodeQueryValueBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	return appendQueryEncoded(make([]byte, 0, len(src)+8), src)
}

// byteSeq constrains the percent-encoder helpers to string and []byte so both
// the string and []byte entry points share one loop with no intermediate copy.
type byteSeq interface{ ~string | ~[]byte }

const hexUpper = "0123456789ABCDEF"

// appendQueryEncoded percent-encodes src for a URL query parameter (unreserved
// passed through, space → '+', everything else → %XX) and appends to dst.
func appendQueryEncoded[T byteSeq](dst []byte, src T) []byte {
	for i := 0; i < len(src); i++ {
		ch := src[i]
		// Unreserved: A-Z, a-z, 0-9, -, _, ., ~
		if (ch >= 'A' && ch <= 'Z') ||
			(ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			dst = append(dst, ch)
			continue
		}
		if ch == ' ' {
			dst = append(dst, '+')
			continue
		}
		dst = append(dst, '%', hexUpper[ch>>4], hexUpper[ch&0x0F])
	}
	return dst
}

// DecodePathValue decodes URL-encoded path segments (RFC 3986).
// Unlike DecodeQueryValue, this does NOT convert '+' to space.
// Use for path segments; use DecodeQueryValue for query/body/cookie params.
//
// RFC 3986 path encoding differs from query string encoding:
//   - Path: '+' is a literal character (no space conversion)
//   - Query: '+' represents space (form-encoding convention)
//
// Algorithm:
//  1. Loop through string character by character
//  2. When '%' found, decode next 2 hex characters
//  3. '+' is kept as literal (NOT converted to space)
//  4. Otherwise, copy character as-is
//
// Example:
//
//	DecodePathValue("api/v1%2B2")     // Returns "api/v1+2" (+ stays literal)
//	DecodePathValue("hello%20world") // Returns "hello world"
//	DecodePathValue("user%2Fadmin")  // Returns "user/admin"
//
// Parameters:
//   - encoded: URL-encoded path segment
//
// Returns:
//   - Decoded string
func DecodePathValue(encoded string) string {
	if encoded == "" {
		return ""
	}

	result := make([]byte, 0, len(encoded))

	for i := 0; i < len(encoded); i++ {
		ch := encoded[i]

		// Handle '%XX' hex encoding
		if ch == '%' && i+2 < len(encoded) {
			hex1 := HexCharToValue(encoded[i+1])
			hex2 := HexCharToValue(encoded[i+2])

			if hex1 != -1 && hex2 != -1 {
				result = append(result, byte(hex1*16+hex2))
				i += 2
				continue
			}
		}

		// NO '+' to space conversion (RFC 3986: + is literal in paths)
		result = append(result, ch)
	}

	return string(result)
}

// EncodePathValue encodes a string for safe use in URL path segments (RFC 3986).
// Unlike EncodeQueryValue, this encodes space as '%20' (not '+').
// Use for path segments; use EncodeQueryValue for query/body/cookie params.
//
// RFC 3986 path encoding differs from query string encoding:
//   - Path: space → %20 (percent encoding only)
//   - Query: space → + (form-encoding convention)
//
// Algorithm:
//  1. Loop through string byte by byte
//  2. Encode unreserved characters as-is: A-Z, a-z, 0-9, -, _, ., ~
//  3. Encode everything else (including space and +) as %XX
//
// Example:
//
//	EncodePathValue("hello world")   // Returns "hello%20world"
//	EncodePathValue("v1+2")          // Returns "v1%2B2"
//	EncodePathValue("user/admin")    // Returns "user%2Fadmin"
//
// Parameters:
//   - decoded: String to encode
//
// Returns:
//   - URL-encoded string for path segment
func EncodePathValue(decoded string) string {
	if decoded == "" {
		return ""
	}
	return string(appendPathEncoded(make([]byte, 0, len(decoded)+8), decoded))
}

// EncodePathValueBytes is the []byte-native form of EncodePathValue, avoiding the
// []byte→string→[]byte round trips on the path-parameter fuzzing hot path.
// Returns nil for empty input.
func EncodePathValueBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	return appendPathEncoded(make([]byte, 0, len(src)+8), src)
}

// appendPathEncoded encodes src for a URL path segment (RFC 3986: unreserved
// passed through, everything else — including space and '+' — → %XX) and appends
// to dst.
func appendPathEncoded[T byteSeq](dst []byte, src T) []byte {
	for i := 0; i < len(src); i++ {
		ch := src[i]
		// Unreserved characters (RFC 3986 §2.3): pass through
		if (ch >= 'A' && ch <= 'Z') ||
			(ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			dst = append(dst, ch)
			continue
		}
		// Everything else (including space and +): percent-encode
		dst = append(dst, '%', hexUpper[ch>>4], hexUpper[ch&0x0F])
	}
	return dst
}
