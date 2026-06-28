package httpmsg

import (
	"fmt"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

// firstRequestLine returns the request line (first line) of a raw HTTP request,
// scanning only up to the first CR/LF. GetMethod/GetPath only need the request
// line, so this avoids parsing — and allocating a string copy of — every header
// line via ExtractAllHeaders on the per-probe hot path.
func firstRequestLine(request []byte) string {
	return string(request[:FindLineEnd(request, 0, len(request))])
}

// request_builder_request.go - HTTP request component manipulation
//
// This file contains operations for:
// - Request line: Method, Path, PathOnly, HTTPVersion
// - Query string: GetQueryString, SetQueryString, URLParameter operations
// - Body: GetBody, SetBody, AppendBody operations

// ==================== REQUEST LINE OPERATIONS ====================

// GetMethod extracts the HTTP method from a request.
// Provides direct method access.
//
// Algorithm:
//  1. Extract first header line (request line)
//  2. Parse using parseRequestLineString
//  3. Return method portion
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - HTTP method (e.g., "GET", "POST")
//   - Error if request malformed
//
// Example:
//
//	method, _ := GetMethod(request)
//	// Returns: "GET"
func GetMethod(request []byte) (string, error) {
	if request == nil {
		return "", nil
	}

	// Parse only the request line (first line) — no need to parse all headers.
	method, _, _ := parseRequestLineString(firstRequestLine(request))
	return method, nil
}

// GetPath extracts the full path (including query string) from a request.
// Provides direct path access.
//
// Algorithm:
//  1. Extract first header line (request line)
//  2. Parse using parseRequestLineString
//  3. Return path portion (includes query if present)
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Full path with query (e.g., "/api/users?id=123")
//   - Error if request malformed
//
// Example:
//
//	path, _ := GetPath(request)
//	// Returns: "/api/users?id=123"
func GetPath(request []byte) (string, error) {
	if request == nil {
		return "", nil
	}

	// Parse only the request line (first line) — no need to parse all headers.
	_, path, _ := parseRequestLineString(firstRequestLine(request))
	return path, nil
}

// GetPathOnly extracts the path without query string from a request.
// Provides path-only access.
//
// Algorithm:
//  1. Get full path using GetPath
//  2. Find '?' character
//  3. Return substring before '?'
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Path without query (e.g., "/api/users")
//   - Error if request malformed
//
// Example:
//
//	pathOnly, _ := GetPathOnly(request)
//	// For "/api/users?id=123" returns: "/api/users"
func GetPathOnly(request []byte) (string, error) {
	path, err := GetPath(request)
	if err != nil {
		return "", err
	}

	// Find query separator
	for i := 0; i < len(path); i++ {
		if path[i] == '?' {
			return path[:i], nil
		}
	}

	return path, nil
}

// GetURLFromService constructs a complete URL from raw request bytes and Service.
// Extracts path from raw bytes using GetPath(), then combines with Service data.
//
// Algorithm:
//  1. Extract path with query string from raw request
//  2. Get scheme, host, port from Service
//  3. Construct URL string: scheme://host:port/path
//  4. Parse into urlutil.URL to populate all fields
//
// Parameters:
//   - request: Raw HTTP request bytes
//   - httpService: HTTP service containing host, port, protocol
//
// Returns:
//   - Constructed urlutil.URL with scheme, host, port, path, and query params
//   - Error if request malformed or httpService nil
//
// Example:
//
//	url, err := GetURLFromService(rawRequest, httpService)
//	// For raw request "GET /api/users?id=123 HTTP/1.1" and httpService with https://example.com:8443
//	// Returns: https://example.com:8443/api/users?id=123
func GetURLFromService(request []byte, httpService *Service) (*urlutil.URL, error) {
	if httpService == nil {
		return nil, fmt.Errorf("httpService cannot be nil")
	}

	// Extract full path with query string
	path, err := GetPath(request)
	if err != nil {
		return nil, fmt.Errorf("failed to extract path: %w", err)
	}

	// If path is empty, default to "/"
	if path == "" {
		path = "/"
	}

	scheme := httpService.Protocol()
	host := httpService.Host()
	port := httpService.Port()

	// Build "scheme://host[:port]path" with a strings.Builder rather than two
	// fmt.Sprintf calls (reflection overhead per probe).
	var b strings.Builder
	b.Grow(len(scheme) + 3 + len(host) + 6 + len(path))
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	// Append :port only for non-default ports.
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		b.WriteByte(':')
		b.WriteString(intToString(port))
	}
	b.WriteString(path)

	// Parse into urlutil.URL to populate all fields (including Params)
	return urlutil.ParseAbsoluteURL(b.String(), false)
}

// GetHTTPVersion extracts the HTTP version from a request.
// Provides direct version access.
//
// Algorithm:
//  1. Extract first header line (request line)
//  2. Parse using parseRequestLineString
//  3. Return version portion
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - HTTP version (e.g., "HTTP/1.1")
//   - Error if request malformed
//
// Example:
//
//	version, _ := GetHTTPVersion(request)
//	// Returns: "HTTP/1.1"
func GetHTTPVersion(request []byte) (string, error) {
	if request == nil {
		return "", nil
	}

	// Extract headers
	headers, _, _, err := ExtractAllHeaders(request)
	if err != nil {
		return "", err
	}

	if len(headers) == 0 {
		return "", nil
	}

	// Parse request line
	_, _, version := parseRequestLineString(headers[0])
	return version, nil
}

// SetMethod replaces the HTTP method in a request.
// Provides direct method modification.
//
// Algorithm:
//  1. Extract all headers and body
//  2. Parse current request line
//  3. Build new request line with new method
//  4. Rebuild request with modified line
//
// Parameters:
//   - request: HTTP request bytes
//   - method: New HTTP method (e.g., "POST", "PUT")
//
// Returns:
//   - Modified request with new method
//   - Error if request malformed
//
// Example:
//
//	modified, _ := SetMethod(request, "POST")
//	// Changes "GET /api HTTP/1.1" to "POST /api HTTP/1.1"
func SetMethod(request []byte, method string) ([]byte, error) {
	if request == nil {
		return nil, nil
	}

	// Extract headers and body
	headers, _, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	if len(headers) == 0 {
		return request, nil
	}

	// Parse current request line
	_, path, version := parseRequestLineString(headers[0])

	// Build new request line
	headers[0] = method + " " + path + " " + version

	// Get body if present
	var body []byte
	if bodyOffset < len(request) {
		body = request[bodyOffset:]
	}

	// Rebuild request
	return BuildHttpMessage(headers, body), nil
}

// SetPath replaces the full path (including query string) in a request.
// Provides direct path modification.
//
// Algorithm:
//  1. Extract all headers and body
//  2. Parse current request line
//  3. Build new request line with new path
//  4. Rebuild request with modified line
//
// Parameters:
//   - request: HTTP request bytes
//   - path: New path (can include query string)
//
// Returns:
//   - Modified request with new path
//   - Error if request malformed
//
// Example:
//
//	modified, _ := SetPath(request, "/api/v2/users?id=456")
//	// Changes path from old to new
func SetPath(request []byte, path string) ([]byte, error) {
	if request == nil {
		return nil, nil
	}

	// Extract headers and body
	headers, _, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	if len(headers) == 0 {
		return request, nil
	}

	// Parse current request line
	method, _, version := parseRequestLineString(headers[0])

	// Build new request line
	headers[0] = method + " " + path + " " + version

	// Get body if present
	var body []byte
	if bodyOffset < len(request) {
		body = request[bodyOffset:]
	}

	// Rebuild request
	return BuildHttpMessage(headers, body), nil
}

// SetPathOnly replaces the path portion while preserving the query string.
// Provides path-only modification.
//
// Algorithm:
//  1. Get current full path
//  2. Extract query string if present
//  3. Combine new path with existing query
//  4. Call SetPath with combined result
//
// Parameters:
//   - request: HTTP request bytes
//   - pathOnly: New path without query string
//
// Returns:
//   - Modified request with new path, preserving query
//   - Error if request malformed
//
// Example:
//
//	modified, _ := SetPathOnly(request, "/api/v2/users")
//	// For "/api/users?id=123" changes to "/api/v2/users?id=123"
func SetPathOnly(request []byte, pathOnly string) ([]byte, error) {
	// Get current full path
	currentPath, err := GetPath(request)
	if err != nil {
		return nil, err
	}

	// Find query string
	queryPos := -1
	for i := 0; i < len(currentPath); i++ {
		if currentPath[i] == '?' {
			queryPos = i
			break
		}
	}

	// Build new full path
	var newPath string
	if queryPos != -1 {
		// Preserve existing query string
		newPath = pathOnly + currentPath[queryPos:]
	} else {
		// No query string
		newPath = pathOnly
	}

	return SetPath(request, newPath)
}

// IsMethodType checks if the request uses a specific HTTP method.
// Provides method checking.
//
// Algorithm:
//  1. Extract method using GetMethod
//  2. Compare case-insensitively
//
// Parameters:
//   - request: HTTP request bytes
//   - method: Method to check (e.g., "GET", "POST")
//
// Returns:
//   - true if method matches
//   - Error if request malformed
//
// Example:
//
//	isPost, _ := IsMethodType(request, "POST")
func IsMethodType(request []byte, method string) (bool, error) {
	currentMethod, err := GetMethod(request)
	if err != nil {
		return false, err
	}

	return EqualsCaseInsensitive(currentMethod, method), nil
}

// SwitchMethod changes the request to use a different HTTP method.
// Generalized method switching (beyond GET<->POST).
//
// Algorithm:
//  1. Use SetMethod to change method
//  2. If switching to GET and has body, optionally move params to URL
//  3. If switching from GET to POST, keep params where they are
//
// Note: Unlike ToggleRequestMethod, this doesn't move parameters.
// Use ToggleRequestMethod for GET↔POST with parameter conversion.
//
// Parameters:
//   - request: HTTP request bytes
//   - newMethod: Target HTTP method
//
// Returns:
//   - Modified request with new method
//   - Error if request malformed
//
// Example:
//
//	modified, _ := SwitchMethod(request, "PUT")
//	// Changes method to PUT, keeps params in same locations
func SwitchMethod(request []byte, newMethod string) ([]byte, error) {
	return SetMethod(request, newMethod)
}

// ==================== QUERY STRING OPERATIONS ====================

// GetQueryString extracts the query string portion from a request path.
// Provides direct query access.
//
// Algorithm:
//  1. Get full path using GetPath
//  2. Find '?' character
//  3. Return substring after '?'
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Query string without '?' (e.g., "id=123&name=test")
//   - Error if request malformed
//
// Example:
//
//	query, _ := GetQueryString(request)
//	// For "/api?id=123" returns: "id=123"
func GetQueryString(request []byte) (string, error) {
	path, err := GetPath(request)
	if err != nil {
		return "", err
	}

	// Find query separator
	for i := 0; i < len(path); i++ {
		if path[i] == '?' {
			return path[i+1:], nil
		}
	}

	return "", nil
}

// SetQueryString replaces the query string in a request.
// Provides direct query modification.
//
// Algorithm:
//  1. Get current path without query using GetPathOnly
//  2. Append new query string with '?'
//  3. Call SetPath with combined result
//
// Parameters:
//   - request: HTTP request bytes
//   - query: New query string without '?' (e.g., "id=456&name=new")
//
// Returns:
//   - Modified request with new query string
//   - Error if request malformed
//
// Example:
//
//	modified, _ := SetQueryString(request, "id=456&name=new")
//	// Changes "/api?id=123" to "/api?id=456&name=new"
func SetQueryString(request []byte, query string) ([]byte, error) {
	pathOnly, err := GetPathOnly(request)
	if err != nil {
		return nil, err
	}

	var newPath string
	if query == "" {
		newPath = pathOnly
	} else {
		newPath = pathOnly + "?" + query
	}

	return SetPath(request, newPath)
}

// ClearQueryString removes all query parameters from a request.
// Provides query removal.
//
// Algorithm:
//  1. Get path without query using GetPathOnly
//  2. Set path to path-only value
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Modified request without query string
//   - Error if request malformed
//
// Example:
//
//	modified, _ := ClearQueryString(request)
//	// Changes "/api?id=123&name=test" to "/api"
func ClearQueryString(request []byte) ([]byte, error) {
	return SetQueryString(request, "")
}

// GetURLParameter extracts a single URL parameter value by name.
// Provides direct parameter access without AnalyzeRequest.
//
// Algorithm:
//  1. Get query string
//  2. Use ParseQueryString to parse into parameters
//  3. Find parameter by name
//  4. Return decoded value
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Parameter name to find
//
// Returns:
//   - Parameter value (decoded)
//   - Error if request malformed
//
// Example:
//
//	value, _ := GetURLParameter(request, "id")
//	// For "?id=123&name=test" returns: "123"
func GetURLParameter(request []byte, name string) (string, error) {
	query, err := GetQueryString(request)
	if err != nil {
		return "", err
	}

	if query == "" {
		return "", nil
	}

	// Parse query string using low-level parser (no '?' prefix in query)
	params := ParseQueryParameters([]byte(query))

	// Find parameter by name
	for _, p := range params {
		if p.Name() == name {
			return p.Value(), nil
		}
	}

	return "", nil
}

// HasURLParameter checks if a URL parameter exists.
// Provides parameter existence check.
//
// Algorithm:
//  1. Get URL parameter value
//  2. Return true if found (even if empty value)
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Parameter name to check
//
// Returns:
//   - true if parameter exists
//   - Error if request malformed
//
// Example:
//
//	exists, _ := HasURLParameter(request, "id")
func HasURLParameter(request []byte, name string) (bool, error) {
	query, err := GetQueryString(request)
	if err != nil {
		return false, err
	}

	if query == "" {
		return false, nil
	}

	// Parse query string using low-level parser (no '?' prefix in query)
	params := ParseQueryParameters([]byte(query))

	// Check if parameter exists
	for _, p := range params {
		if p.Name() == name {
			return true, nil
		}
	}

	return false, nil
}

// GetURLParametersMap returns all URL parameters as a map.
// Provides map-based parameter access.
//
// Algorithm:
//  1. Get query string
//  2. Parse using ParseQueryString
//  3. Convert to map (last value wins if duplicates)
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Map of parameter name → value
//   - Error if request malformed
//
// Example:
//
//	params, _ := GetURLParametersMap(request)
//	// For "?id=123&name=test" returns: {"id": "123", "name": "test"}
func GetURLParametersMap(request []byte) (map[string]string, error) {
	query, err := GetQueryString(request)
	if err != nil {
		return nil, err
	}

	if query == "" {
		return make(map[string]string), nil
	}

	// Parse query string using low-level parser (no '?' prefix in query)
	params := ParseQueryParameters([]byte(query))

	// Convert to map
	result := make(map[string]string, len(params))
	for _, p := range params {
		result[p.Name()] = p.Value()
	}

	return result, nil
}

// SetURLParametersMap replaces all URL parameters with those from a map.
// Provides map-based parameter setting.
//
// Algorithm:
//  1. Build query string from map
//  2. URL-encode each name and value
//  3. Join with '&'
//  4. Call SetQueryString
//
// Parameters:
//   - request: HTTP request bytes
//   - params: Map of parameter name → value
//
// Returns:
//   - Modified request with new parameters
//   - Error if request malformed
//
// Example:
//
//	params := map[string]string{"id": "456", "name": "new"}
//	modified, _ := SetURLParametersMap(request, params)
//	// Creates query string "id=456&name=new"
func SetURLParametersMap(request []byte, params map[string]string) ([]byte, error) {
	if len(params) == 0 {
		return SetQueryString(request, "")
	}

	// Build query string
	query := ""
	first := true
	for name, value := range params {
		if !first {
			query += "&"
		}
		query += EncodeQueryValue(name) + "=" + EncodeQueryValue(value)
		first = false
	}

	return SetQueryString(request, query)
}

// AppendURLParameter adds a URL parameter without removing existing ones.
// Provides append operation.
//
// Algorithm:
//  1. Get current query string
//  2. URL-encode new parameter
//  3. Append with '&' separator if query exists
//  4. Call SetQueryString
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Parameter name
//   - value: Parameter value
//
// Returns:
//   - Modified request with appended parameter
//   - Error if request malformed
//
// Example:
//
//	modified, _ := AppendURLParameter(request, "debug", "true")
//	// For "?id=123" creates "?id=123&debug=true"
func AppendURLParameter(request []byte, name, value string) ([]byte, error) {
	query, err := GetQueryString(request)
	if err != nil {
		return nil, err
	}

	encodedParam := EncodeQueryValue(name) + "=" + EncodeQueryValue(value)

	var newQuery string
	if query == "" {
		newQuery = encodedParam
	} else {
		newQuery = query + "&" + encodedParam
	}

	return SetQueryString(request, newQuery)
}

// ==================== BODY OPERATIONS ====================

// GetBody extracts the body portion from an HTTP request.
// Provides direct body access.
//
// Algorithm:
//  1. Find body offset using FindBodyOffset
//  2. Return bytes from offset to end
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Body bytes (empty if no body)
//   - Error if request malformed
//
// Example:
//
//	body, _ := GetBody(request)
//	// Returns body portion as []byte
func GetBody(request []byte) ([]byte, error) {
	if request == nil {
		return nil, nil
	}

	// Find body offset
	bodyOffset := FindBodyOffset(request)

	if bodyOffset == -1 || bodyOffset >= len(request) {
		return []byte{}, nil
	}

	return request[bodyOffset:], nil
}

// GetBodyString extracts the body as a string.
// Provides string body access.
//
// Algorithm:
//  1. Get body bytes using GetBody
//  2. Convert to string
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Body as string
//   - Error if request malformed
//
// Example:
//
//	bodyStr, _ := GetBodyString(request)
func GetBodyString(request []byte) (string, error) {
	body, err := GetBody(request)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// GetBodySize returns the size of the request body.
// Provides body size calculation.
//
// Algorithm:
//  1. Find body offset
//  2. Calculate total length - offset
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Body size in bytes
//   - Error if request malformed
//
// Example:
//
//	size, _ := GetBodySize(request)
func GetBodySize(request []byte) (int, error) {
	if request == nil {
		return 0, nil
	}

	bodyOffset := FindBodyOffset(request)

	if bodyOffset == -1 || bodyOffset >= len(request) {
		return 0, nil
	}

	return len(request) - bodyOffset, nil
}

// HasBody checks if the request contains a body.
// Provides body existence check.
//
// Algorithm:
//  1. Find body offset
//  2. Check if offset is valid and body size > 0
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - true if body exists and has content
//   - Error if request malformed
//
// Example:
//
//	hasBody, _ := HasBody(request)
func HasBody(request []byte) (bool, error) {
	size, err := GetBodySize(request)
	if err != nil {
		return false, err
	}

	return size > 0, nil
}

// SetBody replaces the body of an HTTP request.
// Provides direct body modification.
//
// Algorithm:
//  1. Extract headers
//  2. Build new request with headers + new body
//  3. Update Content-Length header
//
// Parameters:
//   - request: HTTP request bytes
//   - body: New body bytes
//
// Returns:
//   - Modified request with new body
//   - Error if request malformed
//
// Example:
//
//	newBody := []byte("new data")
//	modified, _ := SetBody(request, newBody)
func SetBody(request []byte, body []byte) ([]byte, error) {
	if request == nil {
		return nil, nil
	}

	// Extract headers
	headers, _, _, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	// Build request with new body
	rebuilt := BuildHttpMessage(headers, body)

	// Update Content-Length
	return UpdateContentLength(rebuilt)
}

// SetBodyString replaces the body with a string value.
// Provides string body modification.
//
// Algorithm:
//  1. Convert string to bytes
//  2. Call SetBody
//
// Parameters:
//   - request: HTTP request bytes
//   - body: New body as string
//
// Returns:
//   - Modified request with new body
//   - Error if request malformed
//
// Example:
//
//	modified, _ := SetBodyString(request, "new data")
func SetBodyString(request []byte, body string) ([]byte, error) {
	return SetBody(request, []byte(body))
}

// ClearBody removes the body from an HTTP request.
// Provides body removal.
//
// Algorithm:
//  1. Set body to empty byte array
//  2. Remove Content-Length and Content-Type headers
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Modified request without body
//   - Error if request malformed
//
// Example:
//
//	modified, _ := ClearBody(request)
func ClearBody(request []byte) ([]byte, error) {
	if request == nil {
		return nil, nil
	}

	// Extract headers
	headers, _, _, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	// Remove Content-Length and Content-Type
	headers = removeHeaderFromList(headers, "Content-Length")
	headers = removeHeaderFromList(headers, "Content-Type")

	// Build request with no body
	return BuildHttpMessage(headers, nil), nil
}

// AppendBody appends data to the existing request body.
// Provides body append operation.
//
// Algorithm:
//  1. Get current body
//  2. Append new data
//  3. Set combined body
//
// Parameters:
//   - request: HTTP request bytes
//   - data: Data to append
//
// Returns:
//   - Modified request with appended body
//   - Error if request malformed
//
// Example:
//
//	modified, _ := AppendBody(request, []byte("&extra=data"))
func AppendBody(request []byte, data []byte) ([]byte, error) {
	currentBody, err := GetBody(request)
	if err != nil {
		return nil, err
	}

	newBody := append(currentBody, data...)
	return SetBody(request, newBody)
}

// PrependBody prepends data to the existing request body.
// Provides body prepend operation.
//
// Algorithm:
//  1. Get current body
//  2. Prepend new data
//  3. Set combined body
//
// Parameters:
//   - request: HTTP request bytes
//   - data: Data to prepend
//
// Returns:
//   - Modified request with prepended body
//   - Error if request malformed
//
// Example:
//
//	modified, _ := PrependBody(request, []byte("prefix_"))
func PrependBody(request []byte, data []byte) ([]byte, error) {
	currentBody, err := GetBody(request)
	if err != nil {
		return nil, err
	}

	newBody := append(data, currentBody...)
	return SetBody(request, newBody)
}

// GetURLFromRequest constructs a full URL string from a raw HTTP request.
// Requires the scheme (http/https) since it's not present in raw HTTP request.
//
// Algorithm:
//  1. Extract path with query string from request line
//  2. Extract Host header value
//  3. Combine scheme + host + path
//
// Parameters:
//   - scheme: URL scheme ("http" or "https")
//   - request: Raw HTTP request bytes
//
// Returns:
//   - Full URL string (e.g., "https://example.com/api?id=123")
//   - Empty string if request is malformed
//
// Example:
//
//	url := GetURLFromRequest("https", []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
//	// Returns: "https://example.com/api?id=123"
func GetURLFromRequest(scheme string, request []byte) string {
	if request == nil || scheme == "" {
		return ""
	}

	// Get path from request line
	path, err := GetPath(request)
	if err != nil || path == "" {
		return ""
	}

	// Get Host header
	host, err := GetHost(request)
	if err != nil || host == "" {
		return ""
	}

	// Build full URL
	return scheme + "://" + host + path
}

// GetExtension extracts file extension from request path.
//
// Algorithm:
//  1. Get path without query string
//  2. Find last '.' in path
//  3. Find last '/' in path
//  4. If '.' exists and is after last '/', return extension (including '.')
//  5. Return empty string if no extension
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - File extension including dot (e.g., ".json", ".html")
//   - Empty string if no extension found
//
// Example:
//
//	ext, _ := GetExtension(request)  // "/api/file.json?x=1" → ".json"
//	ext, _ := GetExtension(request)  // "/api/users" → ""
func GetExtension(request []byte) (string, error) {
	pathOnly, err := GetPathOnly(request)
	if err != nil {
		return "", err
	}

	if pathOnly == "" {
		return "", nil
	}

	// Find last dot and slash positions
	lastDot := -1
	lastSlash := -1

	for i := 0; i < len(pathOnly); i++ {
		switch pathOnly[i] {
		case '.':
			lastDot = i
		case '/':
			lastSlash = i
		}
	}

	// Extension must exist and be after the last slash
	if lastDot == -1 || lastDot < lastSlash {
		return "", nil
	}

	// Return extension including the dot
	return pathOnly[lastDot:], nil
}

// AppendToPath appends a segment to path (before query string).
//
// Algorithm:
//  1. Get current path without query
//  2. Get query string if present
//  3. Append segment to path
//  4. Reattach query string
//  5. Return modified request
//
// Parameters:
//   - request: HTTP request bytes
//   - segment: Path segment to append (e.g., "/extra")
//
// Returns:
//   - Modified request with appended path
//   - Error if request malformed
//
// Example:
//
//	req, _ := AppendToPath(request, "/extra")
//	// "/api?id=1" → "/api/extra?id=1"
func AppendToPath(request []byte, segment string) ([]byte, error) {
	if request == nil {
		return nil, nil
	}

	// Get current path without query
	pathOnly, err := GetPathOnly(request)
	if err != nil {
		return nil, err
	}

	// Get query string
	query, err := GetQueryString(request)
	if err != nil {
		return nil, err
	}

	// Append segment to path
	newPath := pathOnly + segment

	// Reattach query if present
	if query != "" {
		newPath = newPath + "?" + query
	}

	return SetPath(request, newPath)
}
