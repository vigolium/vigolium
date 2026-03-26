package httpmsg

// url_parser.go - URL parsing logic
//
// Uses loop-based character-by-character parsing (no regex, no net/url).

// ParsedURL represents a parsed URL with all components and byte offsets.
type ParsedURL struct {
	Protocol string // "http" or "https"
	Host     string // "example.com" or "192.168.1.1"
	Port     int    // 8080 (default: 80 for http, 443 for https)
	Path     string // "/api/users"
	Query    string // "id=123&name=test" (without leading ?)
	Fragment string // "section1" (without leading #)

	// Byte offsets in original URL
	ProtocolStart int
	ProtocolEnd   int
	HostStart     int
	HostEnd       int
	PathStart     int
	PathEnd       int
	QueryStart    int
	QueryEnd      int
	FragmentStart int
	FragmentEnd   int
}

// ParseURL parses a URL byte slice into components.
// Main URL parsing function that handles both absolute and relative URLs.
//
// Parameters:
//   - urlBytes: URL as byte slice (e.g., "http://example.com:8080/path?query#frag")
//
// Returns:
//   - ParsedURL with all components extracted
//   - error if URL is malformed
//
// Algorithm:
//  1. Parse protocol (http:// or https://)
//  2. Parse host and port
//  3. Parse path
//  4. Parse query string (after ?)
//  5. Parse fragment (after #)
//
// Example:
//
//	url := []byte("http://example.com:8080/path?query=1#section")
//	parsed, _ := ParseURL(url)
//	// parsed.Protocol = "http"
//	// parsed.Host = "example.com"
//	// parsed.Port = 8080
//	// parsed.Path = "/path"
//	// parsed.Query = "query=1"
//	// parsed.Fragment = "section"
func ParseURL(urlBytes []byte) (*ParsedURL, error) {
	if len(urlBytes) == 0 {
		return nil, nil
	}

	parsed := &ParsedURL{
		ProtocolStart: -1,
		ProtocolEnd:   -1,
		HostStart:     -1,
		HostEnd:       -1,
		PathStart:     -1,
		PathEnd:       -1,
		QueryStart:    -1,
		QueryEnd:      -1,
		FragmentStart: -1,
		FragmentEnd:   -1,
	}

	// Step 1: Parse protocol (http:// or https://)
	// Check for "://" sequence
	protocolEnd := FindProtocolEnd(urlBytes)

	if protocolEnd > 0 {
		// Absolute URL with protocol
		parsed.ProtocolStart = 0
		parsed.ProtocolEnd = protocolEnd
		parsed.Protocol = ToLowerString(string(urlBytes[0:protocolEnd]))
		parsed.HostStart = protocolEnd + 3 // Skip "://"
	} else {
		// Relative URL (no protocol)
		parsed.HostStart = 0
		parsed.Protocol = "" // Will be inferred from context
	}

	// Step 2: Parse host and port
	parsed.HostEnd = FindHostEnd(urlBytes, parsed.HostStart)

	if parsed.HostEnd > parsed.HostStart {
		hostBytes := urlBytes[parsed.HostStart:parsed.HostEnd]
		parsed.Host, parsed.Port = ParseHostPort(hostBytes)
	}

	// Apply default port if not specified
	if parsed.Port == -1 && parsed.Protocol != "" {
		parsed.Port = GetDefaultPort(parsed.Protocol)
	}

	// Step 3: Parse path
	parsed.PathStart = parsed.HostEnd
	parsed.PathEnd = FindPathEnd(urlBytes, parsed.PathStart)

	if parsed.PathEnd > parsed.PathStart {
		parsed.Path = string(urlBytes[parsed.PathStart:parsed.PathEnd])
	}

	// Step 4: Parse query string (after ?)
	if parsed.PathEnd < len(urlBytes) && urlBytes[parsed.PathEnd] == '?' {
		parsed.QueryStart = parsed.PathEnd + 1 // Skip '?'
		parsed.QueryEnd = FindQueryEnd(urlBytes, parsed.QueryStart)

		if parsed.QueryEnd > parsed.QueryStart {
			parsed.Query = string(urlBytes[parsed.QueryStart:parsed.QueryEnd])
		}
	} else {
		parsed.QueryStart = -1
		parsed.QueryEnd = parsed.PathEnd
	}

	// Step 5: Parse fragment (after #)
	if parsed.QueryEnd < len(urlBytes) && urlBytes[parsed.QueryEnd] == '#' {
		parsed.FragmentStart = parsed.QueryEnd + 1 // Skip '#'
		parsed.FragmentEnd = len(urlBytes)

		if parsed.FragmentEnd > parsed.FragmentStart {
			parsed.Fragment = string(urlBytes[parsed.FragmentStart:parsed.FragmentEnd])
		}
	} else {
		parsed.FragmentStart = -1
		parsed.FragmentEnd = parsed.QueryEnd
	}

	return parsed, nil
}

// FindProtocolEnd finds the end position of the protocol (before ://).
// Loop-based implementation (no regex).
//
// Parameters:
//   - url: URL bytes to search
//
// Returns:
//   - Position of ':' in "://", or -1 if not found
//
// Algorithm:
//  1. Loop through bytes looking for "://" sequence
//  2. Return position of ':' when found
//  3. Return -1 if not found
//
// Example:
//
//	url := []byte("http://example.com")
//	pos := FindProtocolEnd(url)
//	// Returns 4 (position of ':' in "http:")
func FindProtocolEnd(url []byte) int {
	// Need at least 3 characters for "://"
	if len(url) < 3 {
		return -1
	}

	// Loop-based search for "://" sequence
	// Check for "://" sequence
	for i := 0; i < len(url)-2; i++ {
		if url[i] == ':' && url[i+1] == '/' && url[i+2] == '/' {
			return i
		}
	}

	return -1
}

// FindHostEnd finds the end position of the host:port portion.
// Loop until '/', '?', '#', or end of string.
//
// Parameters:
//   - url: URL bytes
//   - hostStart: Position where host begins
//
// Returns:
//   - Position where host:port ends
//
// Algorithm:
//  1. Loop from hostStart until path/query/fragment delimiter
//  2. Check for '/', '?', '#'
//  3. Return position of delimiter or end of string
//
// Example:
//
//	url := []byte("example.com:8080/path")
//	end := FindHostEnd(url, 0)
//	// Returns 16 (position of '/')
func FindHostEnd(url []byte, hostStart int) int {
	// Loop until delimiter or end
	for i := hostStart; i < len(url); i++ {
		ch := url[i]
		// Check for path/query/fragment delimiters
		if ch == '/' || ch == '?' || ch == '#' {
			return i
		}
	}

	// No delimiter found, return length
	return len(url)
}

// ParseHostPort extracts host and port from "host:port" string.
// Loop-based parsing (no strings.Split or strconv).
//
// Parameters:
//   - hostBytes: Bytes containing host:port (e.g., "example.com:8080")
//
// Returns:
//   - host: Hostname or IP address
//   - port: Port number, or -1 if not specified
//
// Algorithm:
//  1. Find ':' separator using loop
//  2. Extract host before ':'
//  3. Extract port after ':' and parse as integer
//  4. Return -1 for port if no ':' found
//
// Example:
//
//	hostBytes := []byte("example.com:8080")
//	host, port := ParseHostPort(hostBytes)
//	// host = "example.com", port = 8080
//
//	hostBytes := []byte("example.com")
//	host, port := ParseHostPort(hostBytes)
//	// host = "example.com", port = -1
func ParseHostPort(hostBytes []byte) (host string, port int) {
	if len(hostBytes) == 0 {
		return "", -1
	}

	// Find ':' separator using loop
	colonPos := -1
	for i := 0; i < len(hostBytes); i++ {
		if hostBytes[i] == ':' {
			colonPos = i
			break
		}
	}

	if colonPos == -1 {
		// No port specified
		return string(hostBytes), -1
	}

	// Extract host and port
	host = string(hostBytes[0:colonPos])
	portStr := string(hostBytes[colonPos+1:])

	// Parse port using loop-based integer parsing
	port = ParseInt(portStr)

	return host, port
}

// ParseInt parses an integer string using loops (no strconv.Atoi).
// Loop-based digit-by-digit parsing.
//
// Parameters:
//   - s: String containing digits
//
// Returns:
//   - Parsed integer, or -1 if invalid
//
// Algorithm:
//  1. Loop through each character
//  2. Check if character is digit (0-9)
//  3. Build result: result = result*10 + digit
//  4. Return -1 if non-digit found
//
// Example:
//
//	port := ParseInt("8080")
//	// Returns 8080
//
//	port := ParseInt("abc")
//	// Returns -1 (invalid)
func ParseInt(s string) int {
	if s == "" {
		return -1
	}

	result := 0

	// Loop-based digit parsing (NO strconv)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= '0' && ch <= '9' {
			result = result*10 + int(ch-'0')
		} else {
			// Invalid character
			return -1
		}
	}

	return result
}

// FindPathEnd finds the end position of the path (before '?' or '#').
// Loop until query or fragment delimiter.
//
// Parameters:
//   - url: URL bytes
//   - pathStart: Position where path begins
//
// Returns:
//   - Position where path ends (before '?' or '#')
//
// Algorithm:
//  1. Loop from pathStart looking for '?' or '#'
//  2. Return position of delimiter
//  3. Return length if no delimiter found
//
// Example:
//
//	url := []byte("/api/users?id=123#section")
//	end := FindPathEnd(url, 0)
//	// Returns 10 (position of '?')
func FindPathEnd(url []byte, pathStart int) int {
	// Loop until query or fragment delimiter
	for i := pathStart; i < len(url); i++ {
		ch := url[i]
		if ch == '?' || ch == '#' {
			return i
		}
	}

	// No delimiter found
	return len(url)
}

// FindQueryEnd finds the end position of the query string (before '#').
// Loop until fragment delimiter.
//
// Parameters:
//   - url: URL bytes
//   - queryStart: Position where query begins (after '?')
//
// Returns:
//   - Position where query ends (before '#')
//
// Algorithm:
//  1. Loop from queryStart looking for '#'
//  2. Also check for newline (byte 10) or space as terminators
//  3. Return position of delimiter
//  4. Return length if no delimiter found
//
// Example:
//
//	url := []byte("id=123&name=test#section")
//	end := FindQueryEnd(url, 0)
//	// Returns 16 (position of '#')
func FindQueryEnd(url []byte, queryStart int) int {
	// Loop until fragment delimiter or whitespace
	for i := queryStart; i < len(url); i++ {
		ch := url[i]
		// Check for fragment delimiter or terminators
		if ch == '#' || ch == 10 || ch <= 32 {
			return i
		}
	}

	// No delimiter found
	return len(url)
}

// GetDefaultPort returns the default port for a protocol.
//
// Parameters:
//   - protocol: Protocol string ("http", "https", etc.)
//
// Returns:
//   - Default port (80 for http, 443 for https)
//   - -1 if protocol is unknown
//
// Algorithm:
//  1. Convert protocol to lowercase using loop
//  2. Check for known protocols
//  3. Return corresponding default port
//
// Example:
//
//	port := GetDefaultPort("HTTP")
//	// Returns 80
//
//	port := GetDefaultPort("https")
//	// Returns 443
func GetDefaultPort(protocol string) int {
	// Convert to lowercase using loop (NO strings.ToLower)
	protocolLower := ToLowerString(protocol)

	switch protocolLower {
	case "http":
		return 80
	case "https":
		return 443
	case "ws":
		return 80
	case "wss":
		return 443
	default:
		return -1
	}
}

// ToLowerString converts a string to lowercase using loops (no strings.ToLower).
//
// Parameters:
//   - s: String to convert
//
// Returns:
//   - Lowercase version of string
//
// Algorithm:
//  1. Create result buffer
//  2. Loop through each character
//  3. Convert uppercase to lowercase using ToLower
//  4. Return result string
//
// Example:
//
//	lower := ToLowerString("HTTP")
//	// Returns "http"
func ToLowerString(s string) string {
	result := make([]byte, len(s))

	// Loop-based lowercase conversion
	for i := 0; i < len(s); i++ {
		result[i] = ToLower(s[i])
	}

	return string(result)
}

// ExtractURLFromRequest extracts URL from HTTP request line.
// Returns URL bytes and their start/end positions.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - url: URL bytes (between first and second space)
//   - urlStart: Position where URL starts
//   - urlEnd: Position where URL ends
//   - error: Any parsing error
//
// Algorithm:
//  1. Skip leading whitespace
//  2. Skip HTTP method (until first space)
//  3. Skip whitespace after method
//  4. Extract URL (until next space)
//  5. Return URL bytes and positions
//
// Example:
//
//	request := []byte("GET /api/users?id=123 HTTP/1.1\r\n...")
//	url, start, end, _ := ExtractURLFromRequest(request)
//	// url = []byte("/api/users?id=123")
//	// start = 4, end = 21
func ExtractURLFromRequest(request []byte) ([]byte, int, int, error) {
	if len(request) == 0 {
		return nil, -1, -1, nil
	}

	pos := 0
	for pos < len(request) {
		ch := request[pos]
		// Check for newline (invalid)
		if ch == 10 {
			return nil, -1, -1, nil
		}
		// Skip whitespace
		if ch == 32 {
			pos++
		} else {
			break
		}
	}

	for pos < len(request) {
		ch := request[pos]
		// Check for newline (invalid)
		if ch == 10 {
			return nil, -1, -1, nil
		}
		// Stop at space (end of method)
		if ch == 32 {
			break
		}
		pos++
	}

	// Skip whitespace after method
	for pos < len(request) && request[pos] == 32 {
		pos++
	}

	urlStart := pos

	for pos < len(request) {
		ch := request[pos]
		// Check for newline (invalid)
		if ch == 10 {
			return nil, -1, -1, nil
		}
		// Stop at space (before HTTP version)
		if ch == 32 {
			break
		}
		pos++
	}

	urlEnd := pos

	// Validate URL bounds
	if urlStart >= urlEnd {
		return nil, -1, -1, nil
	}

	// Extract URL bytes
	url := request[urlStart:urlEnd]

	return url, urlStart, urlEnd, nil
}

// FindQueryStringBounds finds the start and end of query string in URL path.
// Returns indices of '?' and '#' delimiters.
//
// Parameters:
//   - urlPath: URL path bytes (may contain query)
//
// Returns:
//   - queryStart: Position of '?' (or -1 if not found)
//   - queryEnd: Position of '#' or end of string
//
// Algorithm:
//  1. Loop through bytes looking for '?'
//  2. When found, mark start position
//  3. Continue looking for '#' or whitespace
//  4. Return [start, end] or nil if no query
//
// Example:
//
//	path := []byte("/api/users?id=123#section")
//	start, end := FindQueryStringBounds(path)
//	// start = 10, end = 17
func FindQueryStringBounds(urlPath []byte) (queryStart int, queryEnd int) {
	if len(urlPath) == 0 {
		return -1, -1
	}

	pos := 0
	for pos < len(urlPath) {
		ch := urlPath[pos]

		// Check for newline (end of URL)
		if ch == 10 {
			return -1, -1
		}

		// Check for fragment (no query string)
		if ch == '#' {
			return -1, -1
		}

		// Check for query start
		if ch == '?' {
			queryStart = pos

			// Find query end 
			pos++
			for pos < len(urlPath) {
				ch := urlPath[pos]
				// Stop at whitespace or fragment
				if ch <= 32 || ch == '#' {
					queryEnd = pos
					return queryStart, queryEnd
				}
				pos++
			}

			// Query extends to end of string
			queryEnd = len(urlPath)
			return queryStart, queryEnd
		}

		pos++
	}

	// No query string found
	return -1, -1
}

// IsAbsoluteURL checks if URL has a protocol.
//
// Parameters:
//   - urlBytes: URL bytes to check
//
// Returns:
//   - true if URL starts with "http://" or "https://"
//
// Example:
//
//	isAbs := IsAbsoluteURL([]byte("http://example.com"))
//	// Returns true
//
//	isAbs := IsAbsoluteURL([]byte("/path"))
//	// Returns false
func IsAbsoluteURL(urlBytes []byte) bool {
	return FindProtocolEnd(urlBytes) != -1
}

// IsRelativeURL checks if URL is relative (no protocol).
//
// Parameters:
//   - urlBytes: URL bytes to check
//
// Returns:
//   - true if URL has no protocol
//
// Example:
//
//	isRel := IsRelativeURL([]byte("/path"))
//	// Returns true
//
//	isRel := IsRelativeURL([]byte("http://example.com"))
//	// Returns false
func IsRelativeURL(urlBytes []byte) bool {
	return FindProtocolEnd(urlBytes) == -1
}

// String reconstructs full URL from parsed components (implements fmt.Stringer).
//
// Example:
//
//	parsed := &ParsedURL{
//	    Protocol: "http",
//	    Host: "example.com",
//	    Port: 80,
//	    Path: "/path",
//	    Query: "id=123",
//	    Fragment: "section",
//	}
//	url := parsed.String()
//	// Returns "http://example.com/path?id=123#section"
func (p *ParsedURL) String() string {
	result := ""

	// Add protocol and host
	if p.Protocol != "" {
		result += p.Protocol + "://" + p.Host

		// Add port if not default
		defaultPort := GetDefaultPort(p.Protocol)
		if p.Port != defaultPort && p.Port > 0 {
			result += ":" + IntToString(p.Port)
		}
	}

	// Add path
	if p.Path != "" {
		result += p.Path
	}

	// Add query
	if p.Query != "" {
		result += "?" + p.Query
	}

	// Add fragment
	if p.Fragment != "" {
		result += "#" + p.Fragment
	}

	return result
}

// IntToString converts integer to string using loops (NO strconv.Itoa).
//
// Parameters:
//   - n: Integer to convert
//
// Returns:
//   - String representation
func IntToString(n int) string {
	if n == 0 {
		return "0"
	}

	if n < 0 {
		return "-" + IntToString(-n)
	}

	// Build digits in reverse
	digits := []byte{}
	for n > 0 {
		digit := byte('0' + (n % 10))
		digits = append([]byte{digit}, digits...)
		n = n / 10
	}

	return string(digits)
}

// PathOnly returns path component without query string.
func (p *ParsedURL) PathOnly() string {
	return p.Path
}

// PathWithQuery returns path with query string.
func (p *ParsedURL) PathWithQuery() string {
	if p.Query != "" {
		return p.Path + "?" + p.Query
	}
	return p.Path
}
