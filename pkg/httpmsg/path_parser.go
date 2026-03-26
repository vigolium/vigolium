package httpmsg

// path_parser.go - REST-style path parameter parsing
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
// Algorithm:
//  1. Skip HTTP method
//  2. Skip spaces after method
//  3. Loop through URL path:
//     a. Check for '/' separator
//     b. Find segment end - stop at:
//     - Whitespace (<=32)
//     - Another '/' (path separator)
//     - '?' (query string start)
//     - ';', '&', '=' (URL special chars)
//     c. Classify segment:
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

// parsePathParametersFromRequest is the core path parsing logic for extracting
// REST-style path parameters from HTTP requests.
//
// Algorithm:
//  1. Skip HTTP method
//  2. Skip spaces
//  3. Parse path segments
//  4. Classify as folder or filename
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

	// Step 1: Skip HTTP method (find first space after method)
	for pos < length && request[pos] > 32 {
		pos++
	}

	// Step 2: Skip spaces after method
	for pos < length && request[pos] == 32 {
		pos++
	}

	// Step 3: Parse path segments
	// Loop through URL path character by character
	for pos < length {
		// Check for '/' separator
		if request[pos] != 47 { // 47 is ASCII for '/'
			// No '/' found - end of path
			return params
		}

		// Move past '/' and mark segment start
		pos++
		segmentStart := pos

		// Find segment end
		// Stop at: whitespace, '/', '?', ';', '&', '='
		for pos < length {
			b := request[pos]

			// Stop conditions:
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

		// Create parameter if segment has content
		if pos-segmentStart > 0 {
			// Increment counter for parameter name
			segmentCounter++
			name := intToString(segmentCounter)
			// Decode path segment using RFC 3986 rules (+ stays literal, %XX decoded)
			value := DecodePathValue(string(request[segmentStart:pos]))

			// Classify as folder or filename
			var paramType ParamType
			if pos < length && request[pos] == 47 { // Followed by '/'
				paramType = ParamPathFolder
			} else {
				paramType = ParamPathFilename
			}

			// Create parameter with offsets
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
