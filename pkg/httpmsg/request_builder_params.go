package httpmsg

// request_builder_params.go - HTTP parameter manipulation functions
//
// This file contains all parameter operations:
// - Core: BuildParameter, AddParameter, RemoveParameter, UpdateParameter, ToggleRequestMethod
// - Extensions: Get, Has, GetAll, GetByType, Maps, Append, RemoveAll, AddMultiple

// ==================== CORE PARAMETER OPERATIONS ====================

// BuildParameter creates a new Param object.
//
// Parameters:
//   - name: Parameter name
//   - value: Parameter value
//   - paramType: Parameter type (ParamURL, ParamBody, ParamCookie)
//
// Returns:
//   - Param object ready for use with AddParameter
//
// Example:
//
//	param := BuildParameter("sessionid", "abc123", ParamCookie)
//	request, _ := AddParameter(request, param)
func BuildParameter(name, value string, paramType ParamType) *Param {
	return NewParsedParam(paramType, name, value, -1, -1, -1, -1)
}

// AddParameter adds a parameter to an HTTP request.
//
// Algorithm:
//  1. Analyze request to get current parameters and structure
//  2. Determine where to add parameter based on type
//  3. For ParamURL: Add to query string
//  4. For ParamBody: Add to request body (URL-encoded or multipart)
//  5. For ParamCookie: Add to Cookie header
//  6. Rebuild request with new parameter
//  7. Update Content-Length if body changed
//
// Parameters:
//   - request: Original HTTP request
//   - param: Parameter to add (with Name(), Value(), Type())
//
// Returns:
//   - Modified request with parameter added
//   - Error if request is malformed or parameter type unsupported
//
// Example:
//
//	param := BuildParameter("token", "xyz", ParamURL)
//	modified, _ := AddParameter(request, param)
func AddParameter(request []byte, param *Param) ([]byte, error) {
	if request == nil {
		return nil, nil
	}
	if param == nil {
		return nil, nil
	}

	// Dispatch to appropriate handler based on parameter type
	switch param.Type() {
	case ParamURL:
		return addParameterToURL(request, param)
	case ParamBody:
		return addParameterToBody(request, param)
	case ParamCookie:
		return addParameterToCookie(request, param)
	default:
		// Unsupported parameter type
		return request, nil
	}
}

// RemoveParameter removes a parameter from an HTTP request.
//
// Algorithm:
//  1. Analyze request to get all parameters
//  2. Find parameter to remove by matching name and type
//  3. Remove parameter from appropriate location (URL, body, cookie)
//  4. Update Content-Length if body changed
//
// Parameters:
//   - request: Original HTTP request
//   - param: Parameter to remove (name and type must match)
//
// Returns:
//   - Modified request without the parameter
//   - Error if parameter not found or request malformed
//
// Example:
//
//	param := BuildParameter("debug", "", ParamURL)
//	modified, _ := RemoveParameter(request, param)
func RemoveParameter(request []byte, param *Param) ([]byte, error) {
	if request == nil {
		return nil, nil
	}
	if param == nil {
		return nil, nil
	}

	// Dispatch to appropriate handler based on parameter type
	switch param.Type() {
	case ParamURL:
		return removeParameterFromURL(request, param)
	case ParamBody:
		return removeParameterFromBody(request, param)
	case ParamCookie:
		return removeParameterFromCookie(request, param)
	default:
		return request, nil
	}
}

// UpdateParameter updates a parameter's value in an HTTP request.
//
// Algorithm:
//  1. Remove parameter from request
//  2. Add parameter with new value
//  3. Return modified request
//
// Note: Update is implemented as remove+add, not direct replacement.
// This ensures proper handling of parameter encoding and structure.
//
// Parameters:
//   - request: Original HTTP request
//   - param: Parameter with new value (name, type, and value)
//
// Returns:
//   - Modified request with updated parameter
//   - Error if parameter not found or request malformed
//
// Example:
//
//	param := BuildParameter("version", "2.0", ParamURL)
//	modified, _ := UpdateParameter(request, param)
func UpdateParameter(request []byte, param *Param) ([]byte, error) {
	// Remove then add
	var err error
	request, err = RemoveParameter(request, param)
	if err != nil {
		return nil, err
	}
	return AddParameter(request, param)
}

// ToggleRequestMethod toggles between GET and POST methods.
//
// Algorithm:
//  1. Parse request to get current method and parameters
//  2. Determine new method: GET→POST or POST→GET
//  3. If current method is NOT GET:
//     - Convert BODY params to URL params
//     - URL-encode parameter values
//  4. If current method IS GET:
//     - Convert URL params to BODY params
//  5. Rebuild request with new method
//
// Parameters:
//   - request: HTTP request
//
// Returns:
//   - Request with toggled method
//   - Error if request malformed
//
// Example:
//
//	// GET /api?foo=bar → POST /api with body: foo=bar
//	// POST /api with body: foo=bar → GET /api?foo=bar
//	toggled, _ := ToggleRequestMethod(request)
func ToggleRequestMethod(request []byte) ([]byte, error) {
	if request == nil {
		return nil, nil
	}

	// Analyze request to get method and parameters
	info, err := AnalyzeRequest(request)
	if err != nil {
		return nil, err
	}

	// Determine new method
	currentMethod := info.Method
	isCurrentlyGET := EqualsCaseInsensitive(currentMethod, "GET")

	var newMethod string
	if isCurrentlyGET {
		newMethod = "POST"
	} else {
		newMethod = "GET"
	}

	// Get all parameters
	allParams := info.Parameters

	// Convert parameters based on method change
	convertedParams := make([]*Param, 0, len(allParams))
	for _, p := range allParams {
		newType := p.Type()
		newName := p.Name()
		newValue := p.Value()

		// If changing from non-GET to GET
		if !isCurrentlyGET {
			if p.Type() == ParamBody {
				// Convert body param to URL param
				newType = ParamURL
				// URL-encode the values
				newName = EncodeQueryValue(p.Name())
				newValue = EncodeQueryValue(p.Value())
			}
		} else {
			// Changing from GET to POST
			if p.Type() == ParamURL {
				// Convert URL param to body param
				newType = ParamBody
			}
		}

		newParam := NewParsedParam(newType, newName, newValue,
			p.NameStart(), p.NameEnd(), p.ValueStart(), p.ValueEnd())
		convertedParams = append(convertedParams, newParam)
	}

	// Build new request with converted method and parameters
	return buildRequestWithMethodAndParams(request, info, newMethod, convertedParams)
}

// ==================== HELPER FUNCTIONS ====================

// addParameterToURL adds a parameter to the URL query string.
func addParameterToURL(request []byte, param *Param) ([]byte, error) {
	// Extract headers and body
	headers, _, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	// Get request line (first header)
	if len(headers) == 0 {
		return request, nil
	}

	requestLine := headers[0]

	// Parse request line to extract method, URL, and HTTP version
	// Format: "METHOD /path?query HTTP/version"
	method, url, httpVersion := parseRequestLineString(requestLine)
	if method == "" {
		return request, nil
	}

	// Find query string position in URL
	queryPos := -1
	for i := 0; i < len(url); i++ {
		if url[i] == '?' {
			queryPos = i
			break
		}
	}

	// Build new URL with added parameter
	// Write parameter name and value AS-IS (no encoding).
	// User must pre-encode values if needed.
	var newURL string
	paramStr := param.Name() + "=" + param.Value()

	if queryPos == -1 {
		// No existing query string, add one
		newURL = url + "?" + paramStr
	} else {
		// Append to existing query string
		newURL = url + "&" + paramStr
	}

	// Build new request line
	newRequestLine := method + " " + newURL + " " + httpVersion
	headers[0] = newRequestLine

	// Get body if present
	var body []byte
	if bodyOffset < len(request) {
		body = request[bodyOffset:]
	}

	// Rebuild request
	return BuildHttpMessage(headers, body), nil
}

// addParameterToBody adds a parameter to the request body.
func addParameterToBody(request []byte, param *Param) ([]byte, error) {
	// Extract headers and body
	headers, _, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	// Get body
	var body []byte
	if bodyOffset < len(request) {
		body = request[bodyOffset:]
	}

	// Write parameter name and value AS-IS (no encoding).
	// User must pre-encode values if needed.
	paramStr := param.Name() + "=" + param.Value()

	// Append to body
	var newBody []byte
	if len(body) > 0 {
		// Add separator if body exists
		newBody = append(body, '&')
		newBody = append(newBody, []byte(paramStr)...)
	} else {
		// First parameter in body
		newBody = []byte(paramStr)
		// Ensure Content-Type header exists
		if Header(headers, "Content-Type") == "" {
			headers = append(headers, "Content-Type: application/x-www-form-urlencoded")
		}
	}

	// Rebuild request with new body
	rebuilt := BuildHttpMessage(headers, newBody)

	// Update Content-Length
	return UpdateContentLength(rebuilt)
}

// addParameterToCookie adds a parameter to the Cookie header.
func addParameterToCookie(request []byte, param *Param) ([]byte, error) {
	// Extract headers
	headers, _, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	// Find existing Cookie header
	cookieValue := Header(headers, "Cookie")

	// Write cookie name and value AS-IS (no encoding).
	// User must pre-encode values if needed.
	paramStr := param.Name() + "=" + param.Value()

	if cookieValue == "" {
		// No Cookie header exists, add one
		headers = append(headers, "Cookie: "+paramStr)
	} else {
		// Append to existing Cookie header
		// Remove existing Cookie header
		headers = removeHeaderFromList(headers, "Cookie")
		// Add new Cookie header with appended value
		newCookieValue := cookieValue + "; " + paramStr
		headers = append(headers, "Cookie: "+newCookieValue)
	}

	// Get body if present
	var body []byte
	if bodyOffset < len(request) {
		body = request[bodyOffset:]
	}

	// Rebuild request
	return BuildHttpMessage(headers, body), nil
}

// removeParameterFromURL removes a parameter from the URL query string.
func removeParameterFromURL(request []byte, param *Param) ([]byte, error) {
	// Extract headers and body
	headers, _, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	// Get request line
	if len(headers) == 0 {
		return request, nil
	}

	requestLine := headers[0]
	method, url, httpVersion := parseRequestLineString(requestLine)
	if method == "" {
		return request, nil
	}

	// Find and remove parameter from URL
	newURL := removeParameterFromQueryString(url, param.Name())

	// Build new request line
	newRequestLine := method + " " + newURL + " " + httpVersion
	headers[0] = newRequestLine

	// Get body
	var body []byte
	if bodyOffset < len(request) {
		body = request[bodyOffset:]
	}

	// Rebuild request
	return BuildHttpMessage(headers, body), nil
}

// removeParameterFromBody removes a parameter from the request body.
func removeParameterFromBody(request []byte, param *Param) ([]byte, error) {
	// Extract headers and body
	headers, _, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	// Get body
	var body []byte
	if bodyOffset < len(request) {
		body = request[bodyOffset:]
	}

	// Remove parameter from body (treat as query string format)
	bodyStr := string(body)
	newBodyStr := removeParameterFromQueryString(bodyStr, param.Name())

	// Rebuild request
	rebuilt := BuildHttpMessage(headers, []byte(newBodyStr))

	// Update Content-Length
	return UpdateContentLength(rebuilt)
}

// removeParameterFromCookie removes a parameter from the Cookie header.
func removeParameterFromCookie(request []byte, param *Param) ([]byte, error) {
	// Extract headers
	headers, _, bodyOffset, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	// Find Cookie header
	cookieValue := Header(headers, "Cookie")
	if cookieValue == "" {
		return request, nil
	}

	// Remove parameter from cookie value
	newCookieValue := removeParameterFromCookieString(cookieValue, param.Name())

	// Remove old Cookie header
	headers = removeHeaderFromList(headers, "Cookie")

	// Add new Cookie header if it still has values
	if newCookieValue != "" {
		headers = append(headers, "Cookie: "+newCookieValue)
	}

	// Get body
	var body []byte
	if bodyOffset < len(request) {
		body = request[bodyOffset:]
	}

	// Rebuild request
	return BuildHttpMessage(headers, body), nil
}

// removeParameterFromQueryString removes a parameter from a query string.
// Handles both URL query strings (?foo=bar&baz=qux) and body parameters.
func removeParameterFromQueryString(queryString string, paramName string) string {
	if queryString == "" {
		return ""
	}

	// Find query start position (after '?')
	queryStart := 0
	pathPart := ""
	if idx := indexByte(queryString, '?'); idx != -1 {
		pathPart = queryString[:idx+1]
		queryStart = idx + 1
	}

	// Parse parameters
	result := make([]string, 0)
	start := queryStart
	queryLen := len(queryString)

	// Encode the target name once, not per iteration.
	encodedParamName := EncodeQueryValue(paramName)

	for i := queryStart; i <= queryLen; i++ {
		// Check for separator or end
		if i == queryLen || queryString[i] == '&' {
			if i > start {
				// Extract parameter
				paramPair := queryString[start:i]

				// Parse name from "name=value"
				eqPos := indexByte(paramPair, '=')
				var name string
				if eqPos != -1 {
					name = paramPair[:eqPos]
				} else {
					name = paramPair
				}

				// Keep parameter if name doesn't match
				if name != paramName && name != encodedParamName {
					result = append(result, paramPair)
				}
			}
			start = i + 1
		}
	}

	// Rebuild query string
	if len(result) == 0 {
		// No parameters left, return just path part (or empty)
		if pathPart != "" && pathPart != "?" {
			return pathPart[:len(pathPart)-1] // Remove the '?'
		}
		return ""
	}

	// Join parameters
	newQuery := ""
	for i, param := range result {
		if i > 0 {
			newQuery += "&"
		}
		newQuery += param
	}

	return pathPart + newQuery
}

// removeParameterFromCookieString removes a parameter from a cookie string.
// Cookie format: "name1=value1; name2=value2"
func removeParameterFromCookieString(cookieString string, paramName string) string {
	if cookieString == "" {
		return ""
	}

	result := make([]string, 0)
	start := 0
	cookieLen := len(cookieString)

	// Encode the target name once, not per iteration.
	encodedParamName := EncodeQueryValue(paramName)

	for i := 0; i <= cookieLen; i++ {
		// Check for separator or end
		if i == cookieLen || cookieString[i] == ';' {
			if i > start {
				// Extract parameter
				paramPair := trimSpace(cookieString[start:i])

				// Parse name from "name=value"
				eqPos := indexByte(paramPair, '=')
				var name string
				if eqPos != -1 {
					name = paramPair[:eqPos]
				} else {
					name = paramPair
				}

				// Keep parameter if name doesn't match
				if name != paramName && name != encodedParamName {
					result = append(result, paramPair)
				}
			}
			start = i + 1
		}
	}

	// Rebuild cookie string
	newCookie := ""
	for i, param := range result {
		if i > 0 {
			newCookie += "; "
		}
		newCookie += param
	}

	return newCookie
}

// parseRequestLineString parses an HTTP request line into method, URL, and version string.
// Format: "METHOD /path HTTP/version"
func parseRequestLineString(requestLine string) (method, url, httpVersion string) {
	if requestLine == "" {
		return "", "", ""
	}

	// Find first space (after method)
	firstSpace := -1
	for i := 0; i < len(requestLine); i++ {
		if requestLine[i] == ' ' {
			firstSpace = i
			break
		}
	}

	if firstSpace == -1 {
		return "", "", ""
	}

	method = requestLine[:firstSpace]

	// Find second space (after URL)
	secondSpace := -1
	for i := firstSpace + 1; i < len(requestLine); i++ {
		if requestLine[i] == ' ' {
			secondSpace = i
			break
		}
	}

	if secondSpace == -1 {
		// No HTTP version specified
		url = requestLine[firstSpace+1:]
		httpVersion = "HTTP/1.1"
	} else {
		url = requestLine[firstSpace+1 : secondSpace]
		httpVersion = requestLine[secondSpace+1:]
	}

	return method, url, httpVersion
}

// buildRequestWithMethodAndParams rebuilds a request with a new method and parameters.
func buildRequestWithMethodAndParams(request []byte, info *RequestInfo, newMethod string, params []*Param) ([]byte, error) {
	// Extract headers
	headers, _, _, err := ExtractAllHeaders(request)
	if err != nil {
		return nil, err
	}

	if len(headers) == 0 {
		return request, nil
	}

	// Parse original request line
	requestLine := headers[0]
	_, url, httpVersion := parseRequestLineString(requestLine)

	// Remove query string from URL (will be rebuilt from params)
	baseURL := url
	if idx := indexByte(url, '?'); idx != -1 {
		baseURL = url[:idx]
	}

	// Separate URL params and body params
	urlParams := make([]*Param, 0)
	bodyParams := make([]*Param, 0)
	cookieParams := make([]*Param, 0)

	for _, p := range params {
		switch p.Type() {
		case ParamURL:
			urlParams = append(urlParams, p)
		case ParamBody:
			bodyParams = append(bodyParams, p)
		case ParamCookie:
			cookieParams = append(cookieParams, p)
		}
	}

	// Build URL with query params
	newURL := baseURL
	if len(urlParams) > 0 {
		queryStr := ""
		for i, p := range urlParams {
			if i > 0 {
				queryStr += "&"
			}
			queryStr += EncodeQueryValue(p.Name()) + "=" + EncodeQueryValue(p.Value())
		}
		newURL = baseURL + "?" + queryStr
	}

	// Build new request line
	newRequestLine := newMethod + " " + newURL + " " + httpVersion
	headers[0] = newRequestLine

	// Build body from body params
	var body []byte
	if len(bodyParams) > 0 {
		bodyStr := ""
		for i, p := range bodyParams {
			if i > 0 {
				bodyStr += "&"
			}
			bodyStr += EncodeQueryValue(p.Name()) + "=" + EncodeQueryValue(p.Value())
		}
		body = []byte(bodyStr)

		// Ensure Content-Type header
		if Header(headers, "Content-Type") == "" {
			headers = append(headers, "Content-Type: application/x-www-form-urlencoded")
		}
	}

	// Rebuild cookie header from cookie params
	if len(cookieParams) > 0 {
		// Remove existing cookie header
		headers = removeHeaderFromList(headers, "Cookie")

		// Build new cookie header
		cookieStr := ""
		for i, p := range cookieParams {
			if i > 0 {
				cookieStr += "; "
			}
			cookieStr += EncodeQueryValue(p.Name()) + "=" + EncodeQueryValue(p.Value())
		}
		headers = append(headers, "Cookie: "+cookieStr)
	}

	// Remove Content-Type and Content-Length if no body
	if len(body) == 0 {
		headers = removeHeaderFromList(headers, "Content-Type")
		headers = removeHeaderFromList(headers, "Content-Length")
	}

	// Rebuild request
	rebuilt := BuildHttpMessage(headers, body)

	// Update Content-Length if there's a body
	if len(body) > 0 {
		return UpdateContentLength(rebuilt)
	}

	return rebuilt, nil
}

// ==================== EXTENSION API: PARAMETER OPERATIONS ====================

// GetParameter extracts a single parameter value by name and type.
// Provides direct parameter access without AnalyzeRequest.
//
// Algorithm:
//  1. Call AnalyzeRequest to get all parameters
//  2. Find parameter by name and type
//  3. Return value
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Parameter name
//   - paramType: Parameter type (ParamURL, ParamBody, ParamCookie)
//
// Returns:
//   - Parameter value (decoded)
//   - Error if request malformed
//
// Example:
//
//	value, _ := GetParameter(request, "id", ParamURL)
func GetParameter(request []byte, name string, paramType ParamType) (string, error) {
	info, err := AnalyzeRequest(request)
	if err != nil {
		return "", err
	}

	for _, p := range info.Parameters {
		if p.Name() == name && p.Type() == paramType {
			return p.Value(), nil
		}
	}

	return "", nil
}

// HasParameter checks if a parameter exists.
// Provides parameter existence check.
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Parameter name
//   - paramType: Parameter type
//
// Returns:
//   - true if parameter exists
//   - Error if request malformed
//
// Example:
//
//	exists, _ := HasParameter(request, "debug", ParamURL)
func HasParameter(request []byte, name string, paramType ParamType) (bool, error) {
	info, err := AnalyzeRequest(request)
	if err != nil {
		return false, err
	}

	// Parameter exists even if value is empty
	for _, p := range info.Parameters {
		if p.Name() == name && p.Type() == paramType {
			return true, nil
		}
	}

	return false, nil
}

// GetParameterOrDefault returns parameter value or default if not found.
// Provides parameter access with fallback.
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Parameter name
//   - paramType: Parameter type
//   - defaultVal: Default value if parameter not found
//
// Returns:
//   - Parameter value or default
//
// Example:
//
//	limit := GetParameterOrDefault(request, "limit", ParamURL, "10")
func GetParameterOrDefault(request []byte, name string, paramType ParamType, defaultVal string) string {
	value, err := GetParameter(request, name, paramType)
	if err != nil || value == "" {
		return defaultVal
	}

	return value
}

// GetAllParameters returns all parameters from a request.
// Wrapper for AnalyzeRequest.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - All parameters
//   - Error if request malformed
//
// Example:
//
//	params, _ := GetAllParameters(request)
func GetAllParameters(request []byte) ([]*Param, error) {
	info, err := AnalyzeRequest(request)
	if err != nil {
		return nil, err
	}

	return info.Parameters, nil
}

// GetParametersByType returns all parameters of a specific type.
// Filters parameters by type.
//
// Parameters:
//   - request: HTTP request bytes
//   - paramType: Parameter type to filter
//
// Returns:
//   - Parameters of specified type
//   - Error if request malformed
//
// Example:
//
//	urlParams, _ := GetParametersByType(request, ParamURL)
func GetParametersByType(request []byte, paramType ParamType) ([]*Param, error) {
	allParams, err := GetAllParameters(request)
	if err != nil {
		return nil, err
	}

	var filtered []*Param
	for _, p := range allParams {
		if p.Type() == paramType {
			filtered = append(filtered, p)
		}
	}

	return filtered, nil
}

// GetBodyParametersMap returns all body parameters as a map.
// Provides map-based body parameter access.
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
//	params, _ := GetBodyParametersMap(request)
func GetBodyParametersMap(request []byte) (map[string]string, error) {
	bodyParams, err := GetParametersByType(request, ParamBody)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(bodyParams))
	for _, p := range bodyParams {
		result[p.Name()] = p.Value()
	}

	return result, nil
}

// SetBodyParametersMap replaces all body parameters with those from a map.
// Provides map-based body parameter setting.
//
// Parameters:
//   - request: HTTP request bytes
//   - params: Map of parameter name → value
//
// Returns:
//   - Modified request with new body parameters
//   - Error if request malformed
//
// Example:
//
//	params := map[string]string{"username": "admin", "password": "test"}
//	modified, _ := SetBodyParametersMap(request, params)
func SetBodyParametersMap(request []byte, params map[string]string) ([]byte, error) {
	// Remove all existing body parameters
	modified, err := RemoveAllParametersByType(request, ParamBody)
	if err != nil {
		return nil, err
	}

	// Add new parameters
	for name, value := range params {
		param := BuildParameter(name, value, ParamBody)
		modified, err = AddParameter(modified, param)
		if err != nil {
			return nil, err
		}
	}

	return modified, nil
}

// AppendBodyParameter adds a body parameter without removing existing ones.
// Provides append operation.
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
//	modified, _ := AppendBodyParameter(request, "debug", "true")
func AppendBodyParameter(request []byte, name, value string) ([]byte, error) {
	param := BuildParameter(name, value, ParamBody)
	return AddParameter(request, param)
}

// RemoveAllParametersByType removes all parameters of a specific type.
// Provides batch remove operation.
//
// Parameters:
//   - request: HTTP request bytes
//   - paramType: Parameter type to remove
//
// Returns:
//   - Modified request without parameters of specified type
//   - Error if request malformed
//
// Example:
//
//	modified, _ := RemoveAllParametersByType(request, ParamURL)
func RemoveAllParametersByType(request []byte, paramType ParamType) ([]byte, error) {
	params, err := GetParametersByType(request, paramType)
	if err != nil {
		return nil, err
	}

	modified := request
	for _, p := range params {
		modified, err = RemoveParameter(modified, p)
		if err != nil {
			return nil, err
		}
	}

	return modified, nil
}

// RemoveParametersByName removes all parameters matching names.
// Provides batch name-based removal.
//
// Parameters:
//   - request: HTTP request bytes
//   - names: Parameter names to remove
//   - paramType: Parameter type
//
// Returns:
//   - Modified request without specified parameters
//   - Error if request malformed
//
// Example:
//
//	modified, _ := RemoveParametersByName(request, []string{"debug", "trace"}, ParamURL)
func RemoveParametersByName(request []byte, names []string, paramType ParamType) ([]byte, error) {
	modified := request
	var err error

	for _, name := range names {
		param := BuildParameter(name, "", paramType)
		modified, err = RemoveParameter(modified, param)
		if err != nil {
			return nil, err
		}
	}

	return modified, nil
}

// AddMultipleParameters adds multiple parameters at once.
// Provides batch add operation.
//
// Parameters:
//   - request: HTTP request bytes
//   - params: Parameters to add
//
// Returns:
//   - Modified request with all parameters added
//   - Error if request malformed
//
// Example:
//
//	params := []*Param{BuildParameter("a", "1", ParamURL), BuildParameter("b", "2", ParamURL)}
//	modified, _ := AddMultipleParameters(request, params)
func AddMultipleParameters(request []byte, params []*Param) ([]byte, error) {
	modified := request
	var err error

	for _, p := range params {
		modified, err = AddParameter(modified, p)
		if err != nil {
			return nil, err
		}
	}

	return modified, nil
}
