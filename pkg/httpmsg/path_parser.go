package httpmsg

// path_parser.go - REST-style path parameter parsing ported from Burp Suite
// Ported from: burp/c9s.java method c(bi9 var0) (lines 489-550)
//              burp/etq.java method a(byte[] var0) wrapper (line 30-32)
//
// This parser extracts REST-style path parameters from HTTP request URLs.
// It splits URL paths by '/' and creates parameters for each segment.
//
// Example:
//   GET /api/users/123/profile?id=5 HTTP/1.1
//   Extracts:
//     - Param{Name: "1", Value: "api", Type: ParamPathFolder}
//     - Param{Name: "2", Value: "users", Type: ParamPathFolder}
//     - Param{Name: "3", Value: "123", Type: ParamPathFolder}
//     - Param{Name: "4", Value: "profile", Type: ParamPathFilename}

// ParsePathParameters extracts REST-style path parameters from an HTTP request.
// This function parses the URL path (not query string) and creates parameters
// for each path segment separated by '/'.
//
// Ported from: c9s.java method c(bi9) (lines 489-550)
// Wrapper from: etq.java method a(byte[]) (lines 30-32)
//
// Algorithm (from c9s.java):
//  1. Skip HTTP method (lines 496-502)
//  2. Skip spaces after method (lines 504-509)
//  3. Loop through URL path (lines 513-547):
//     a. Check for '/' separator (line 514)
//     b. Find segment end (lines 520-530) - stop at:
//     - Whitespace (<=32)
//     - Another '/' (path separator)
//     - '?' (query string start)
//     - ';', '&', '=' (URL special chars)
//     c. Classify segment (lines 533-541):
//     - If followed by '/' → PATH_FOLDER_PARAM
//     - If NOT followed by '/' → PATH_FILENAME_PARAM
//     d. Create parameter with sequential integer name
//  4. Return list of path parameters
//
// Classification logic:
//   - PATH_FOLDER: segment followed by another '/' (e.g., /api/ in /api/users)
//   - PATH_FILENAME: last segment or segment before query/fragment (e.g., profile in /api/profile)
//
// Example:
//
//	request := []byte("GET /api/users/123/profile HTTP/1.1\r\nHost: example.com\r\n\r\n")
//	params, err := ParsePathParameters(request)
//	// Returns:
//	//   [0] = {Type: ParamPathFolder, Name: "1", Value: "api", ValueStart: 5, ValueEnd: 8}
//	//   [1] = {Type: ParamPathFolder, Name: "2", Value: "users", ValueStart: 9, ValueEnd: 14}
//	//   [2] = {Type: ParamPathFolder, Name: "3", Value: "123", ValueStart: 15, ValueEnd: 18}
//	//   [3] = {Type: ParamPathFilename, Name: "4", Value: "profile", ValueStart: 19, ValueEnd: 26}
//
// Parameters:
//   - request: Complete HTTP request bytes including headers and body
//
// Returns:
//   - List of Param objects with ParamPathFolder or ParamPathFilename types
//   - Error if parsing fails (currently never returns error for compatibility)
func ParsePathParameters(request []byte) ([]*Param, error) {
	if len(request) == 0 {
		return []*Param{}, nil
	}

	// Parse using low-level function
	params := parsePathParametersFromRequest(request)
	return params, nil
}

// parsePathParametersFromRequest is the core path parsing logic.
// Ported from: c9s.java method c(bi9) (lines 489-550)
//
// This implements the exact algorithm from Burp Suite for extracting
// REST-style path parameters from HTTP requests.
//
// Algorithm steps (matching c9s.java line-by-line):
//  1. Skip HTTP method (lines 496-502)
//  2. Skip spaces (lines 504-509)
//  3. Parse path segments (lines 513-547)
//  4. Classify as folder or filename (lines 533-541)
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - List of path parameters
func parsePathParametersFromRequest(request []byte) []*Param {
	params := []*Param{}
	pos := 0
	length := len(request)
	segmentCounter := 0 // Used for sequential parameter names: "1", "2", "3", ...

	// Step 1: Skip HTTP method (c9s.java lines 496-502)
	// Find first space after method (GET, POST, etc.)
	for pos < length && request[pos] > 32 {
		pos++
	}

	// Step 2: Skip spaces after method (c9s.java lines 504-509)
	for pos < length && request[pos] == 32 {
		pos++
	}

	// Step 3: Parse path segments (c9s.java lines 513-547)
	// Loop through URL path character by character
	for pos < length {
		// Check for '/' separator (c9s.java line 514)
		if request[pos] != 47 { // 47 is ASCII for '/'
			// No '/' found - end of path
			return params
		}

		// Move past '/' and mark segment start (c9s.java line 518)
		pos++
		segmentStart := pos

		// Find segment end (c9s.java lines 520-530)
		// Stop at: whitespace, '/', '?', ';', '&', '='
		for pos < length {
			b := request[pos]

			// Stop conditions (c9s.java line 522):
			// - Whitespace (<=32)
			// - '/' (47) - next path separator
			// - '?' (63) - query string start
			// - ';' (59) - path parameter separator
			// - '&' (38) - query separator
			// - '=' (61) - query separator
			if b <= 32 || b == 47 || b == 63 || b == 59 || b == 38 || b == 61 {
				break
			}

			pos++
		}

		// Create parameter if segment has content (c9s.java lines 533-541)
		if pos-segmentStart > 0 {
			// Increment counter for parameter name
			segmentCounter++
			name := intToString(segmentCounter)
			// Decode path segment using RFC 3986 rules (+ stays literal, %XX decoded)
			value := DecodePathValue(string(request[segmentStart:pos]))

			// Classify as folder or filename (c9s.java lines 534-541)
			var paramType ParamType
			if pos < length && request[pos] == 47 { // Followed by '/' (line 534)
				// This is a folder parameter (line 541)
				paramType = ParamPathFolder
			} else {
				// This is a filename parameter (line 535)
				paramType = ParamPathFilename
			}

			// Create parameter with offsets (c9s.java line 535, 541)
			// Note: NameStart and NameEnd are -1 because path params don't have
			// explicit names in the URL (name is the sequential integer)
			param := NewParsedParam(
				paramType,
				name,
				value,
				-1, // No explicit name in URL
				-1, // No explicit name in URL
				segmentStart,
				pos,
			)
			params = append(params, param)
		}
	}

	return params
}
