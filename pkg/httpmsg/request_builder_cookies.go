package httpmsg

import "errors"

// request_builder_cookies.go - Cookie operations and request validation
//
// This file contains:
// - Cookie operations: Get, GetAll, Has, Set, Remove, SetAll
// - Validation: ValidateRequest, ValidateRequestLine, ValidateHeaders
// - Inspection: GetRequestSize, GetHeadersSize, GetBodyOffset, IsWellFormed

// ==================== COOKIE OPERATIONS ====================

// GetCookie extracts a single cookie value by name.
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Cookie name
//
// Returns:
//   - Cookie value
//   - Error if request malformed
//
// Example:
//
//	sessionId, _ := GetCookie(request, "JSESSIONID")
func GetCookie(request []byte, name string) (string, error) {
	return GetParameter(request, name, ParamCookie)
}

// GetAllCookies returns all cookies as a map.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Map of cookie name → value
//   - Error if request malformed
//
// Example:
//
//	cookies, _ := GetAllCookies(request)
func GetAllCookies(request []byte) (map[string]string, error) {
	cookieParams, err := GetParametersByType(request, ParamCookie)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(cookieParams))
	for _, p := range cookieParams {
		result[p.Name()] = p.Value()
	}

	return result, nil
}

// HasCookie checks if a cookie exists.
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Cookie name
//
// Returns:
//   - true if cookie exists
//   - Error if request malformed
//
// Example:
//
//	hasSess, _ := HasCookie(request, "session")
func HasCookie(request []byte, name string) (bool, error) {
	return HasParameter(request, name, ParamCookie)
}

// SetCookie sets or updates a cookie.
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Cookie name
//   - value: Cookie value
//
// Returns:
//   - Modified request with cookie set
//   - Error if request malformed
//
// Example:
//
//	modified, _ := SetCookie(request, "session", "abc123")
func SetCookie(request []byte, name, value string) ([]byte, error) {
	param := BuildParameter(name, value, ParamCookie)
	return UpdateParameter(request, param)
}

// RemoveCookie removes a cookie.
//
// Parameters:
//   - request: HTTP request bytes
//   - name: Cookie name
//
// Returns:
//   - Modified request without cookie
//   - Error if request malformed
//
// Example:
//
//	modified, _ := RemoveCookie(request, "tracking")
func RemoveCookie(request []byte, name string) ([]byte, error) {
	param := BuildParameter(name, "", ParamCookie)
	return RemoveParameter(request, param)
}

// SetAllCookies replaces all cookies with those from a map.
//
// Parameters:
//   - request: HTTP request bytes
//   - cookies: Map of cookie name → value
//
// Returns:
//   - Modified request with new cookies
//   - Error if request malformed
//
// Example:
//
//	cookies := map[string]string{"session": "abc", "tracking": "xyz"}
//	modified, _ := SetAllCookies(request, cookies)
func SetAllCookies(request []byte, cookies map[string]string) ([]byte, error) {
	// Remove all existing cookies
	modified, err := RemoveAllParametersByType(request, ParamCookie)
	if err != nil {
		return nil, err
	}

	// Add new cookies
	for name, value := range cookies {
		param := BuildParameter(name, value, ParamCookie)
		modified, err = AddParameter(modified, param)
		if err != nil {
			return nil, err
		}
	}

	return modified, nil
}

// ==================== VALIDATION & INSPECTION ====================

// ValidateRequest checks if a request is well-formed.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Error if request is malformed, nil if valid
//
// Example:
//
//	if err := ValidateRequest(request); err != nil {
//	    // Handle invalid request
//	}
func ValidateRequest(request []byte) error {
	// Try to analyze request
	_, err := AnalyzeRequest(request)
	return err
}

// ValidateRequestLine checks if the request line is well-formed.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Error if request line malformed, nil if valid
//
// Example:
//
//	if err := ValidateRequestLine(request); err != nil {
//	    // Handle invalid request line
//	}
func ValidateRequestLine(request []byte) error {
	method, err := GetMethod(request)
	if err != nil {
		return err
	}

	if method == "" {
		return errors.New("empty HTTP method")
	}

	path, err := GetPath(request)
	if err != nil {
		return err
	}

	if path == "" {
		return errors.New("empty request path")
	}

	version, err := GetHTTPVersion(request)
	if err != nil {
		return err
	}

	if version == "" {
		return errors.New("empty HTTP version")
	}

	return nil
}

// ValidateHeaders checks if headers are well-formed.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Error if headers malformed, nil if valid
//
// Example:
//
//	if err := ValidateHeaders(request); err != nil {
//	    // Handle invalid headers
//	}
func ValidateHeaders(request []byte) error {
	_, _, _, err := ExtractAllHeaders(request)
	return err
}

// GetRequestSize returns the total size of the request.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Request size in bytes
//
// Example:
//
//	size := GetRequestSize(request)
func GetRequestSize(request []byte) int {
	return len(request)
}

// GetHeadersSize returns the size of headers (including request line).
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Headers size in bytes
//   - Error if request malformed
//
// Example:
//
//	size, _ := GetHeadersSize(request)
func GetHeadersSize(request []byte) (int, error) {
	bodyOffset := FindBodyOffset(request)
	if bodyOffset == -1 {
		return len(request), nil
	}

	return bodyOffset, nil
}

// GetBodyOffset returns the offset where the body starts.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Body offset (-1 if no body)
//   - Error if request malformed
//
// Example:
//
//	offset, _ := GetBodyOffset(request)
func GetBodyOffset(request []byte) (int, error) {
	offset := FindBodyOffset(request)
	return offset, nil
}

// IsWellFormed checks if request is well-formed (convenience wrapper).
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - true if request is valid
//
// Example:
//
//	if IsWellFormed(request) {
//	    // Process request
//	}
func IsWellFormed(request []byte) bool {
	return ValidateRequest(request) == nil
}
