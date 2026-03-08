package httpmsg

import (
	"bytes"
	"testing"
)

// ==================== REQUEST LINE OPERATIONS TESTS ====================

// TestGetMethod tests extracting HTTP method from requests
func TestGetMethod(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "GET request",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "GET",
			wantErr:  false,
		},
		{
			name:     "POST request",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "POST",
			wantErr:  false,
		},
		{
			name:     "PUT request",
			request:  []byte("PUT /api/users/1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "PUT",
			wantErr:  false,
		},
		{
			name:     "DELETE request",
			request:  []byte("DELETE /api/users/1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "DELETE",
			wantErr:  false,
		},
		{
			name:     "PATCH request",
			request:  []byte("PATCH /api/users/1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "PATCH",
			wantErr:  false,
		},
		{
			name:     "HEAD request",
			request:  []byte("HEAD /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "HEAD",
			wantErr:  false,
		},
		{
			name:     "OPTIONS request",
			request:  []byte("OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "OPTIONS",
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "empty request",
			request:  []byte(""),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "request with HTTP/2",
			request:  []byte("GET /api HTTP/2.0\r\nHost: example.com\r\n\r\n"),
			expected: "GET",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetMethod(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("GetMethod() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestGetPath tests extracting full path (with query string) from requests
func TestGetPath(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "simple path",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/api",
			wantErr:  false,
		},
		{
			name:     "path with query string",
			request:  []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/api?id=123&name=test",
			wantErr:  false,
		},
		{
			name:     "root path",
			request:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/",
			wantErr:  false,
		},
		{
			name:     "nested path",
			request:  []byte("GET /api/v2/users/123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/api/v2/users/123",
			wantErr:  false,
		},
		{
			name:     "path with encoded characters",
			request:  []byte("GET /api/search?q=hello%20world HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/api/search?q=hello%20world",
			wantErr:  false,
		},
		{
			name:     "path with fragment (should include)",
			request:  []byte("GET /api#section HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/api#section",
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "empty request",
			request:  []byte(""),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "asterisk for OPTIONS",
			request:  []byte("OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "*",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetPath(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("GetPath() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestGetPathOnly tests extracting path without query string
func TestGetPathOnly(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "path with query string",
			request:  []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/api",
			wantErr:  false,
		},
		{
			name:     "path without query string",
			request:  []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/api/users",
			wantErr:  false,
		},
		{
			name:     "root path with query",
			request:  []byte("GET /?page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/",
			wantErr:  false,
		},
		{
			name:     "complex query string",
			request:  []byte("GET /search?q=test&filter=active&sort=desc HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/search",
			wantErr:  false,
		},
		{
			name:     "empty query string",
			request:  []byte("GET /api? HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "/api",
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetPathOnly(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("GetPathOnly() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestGetHTTPVersion tests extracting HTTP version from requests
func TestGetHTTPVersion(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "HTTP/1.1",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "HTTP/1.1",
			wantErr:  false,
		},
		{
			name:     "HTTP/1.0",
			request:  []byte("GET /api HTTP/1.0\r\nHost: example.com\r\n\r\n"),
			expected: "HTTP/1.0",
			wantErr:  false,
		},
		{
			name:     "HTTP/2.0",
			request:  []byte("GET /api HTTP/2.0\r\nHost: example.com\r\n\r\n"),
			expected: "HTTP/2.0",
			wantErr:  false,
		},
		{
			name:     "HTTP/2",
			request:  []byte("GET /api HTTP/2\r\nHost: example.com\r\n\r\n"),
			expected: "HTTP/2",
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "empty request",
			request:  []byte(""),
			expected: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetHTTPVersion(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("GetHTTPVersion() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestSetMethod tests changing HTTP method
func TestSetMethod(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		newMethod string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:      "change GET to POST",
			request:   []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newMethod: "POST",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("POST /api HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:      "change POST to PUT",
			request:   []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nbody"),
			newMethod: "PUT",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("PUT /api HTTP/1.1\r\n")) &&
					bytes.Contains(result, []byte("body"))
			},
			wantErr: false,
		},
		{
			name:      "change to DELETE",
			request:   []byte("GET /api/users/1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newMethod: "DELETE",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("DELETE /api/users/1 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:      "preserve query string",
			request:   []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newMethod: "POST",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("POST /api?id=123 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:      "nil request",
			request:   nil,
			newMethod: "POST",
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetMethod(tt.request, tt.newMethod)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("SetMethod() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestSetPath tests changing request path
func TestSetPath(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		newPath   string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "change simple path",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newPath: "/api/v2",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api/v2 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "change path with query string",
			request: []byte("GET /api?old=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newPath: "/api/v2?new=456",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api/v2?new=456 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "remove query string",
			request: []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newPath: "/api",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "add query string",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newPath: "/api?id=123",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api?id=123 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "preserve method and body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nbody data"),
			newPath: "/api/v2",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("POST /api/v2 HTTP/1.1\r\n")) &&
					bytes.Contains(result, []byte("body data"))
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			newPath: "/api",
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetPath(tt.request, tt.newPath)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("SetPath() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestSetPathOnly tests changing path while preserving query string
func TestSetPathOnly(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		newPath   string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "change path preserving query",
			request: []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newPath: "/api/v2/users",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api/v2/users?id=123&name=test HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "change path with no query",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newPath: "/api/v2",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api/v2 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "change to root path preserving query",
			request: []byte("GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newPath: "/",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /?page=1 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "complex query preserved",
			request: []byte("GET /old?a=1&b=2&c=3 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newPath: "/new",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /new?a=1&b=2&c=3 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			newPath: "/api",
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetPathOnly(tt.request, tt.newPath)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("SetPathOnly() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestIsMethodType tests checking HTTP method
func TestIsMethodType(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		method   string
		expected bool
		wantErr  bool
	}{
		{
			name:     "GET matches GET",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			method:   "GET",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "GET does not match POST",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			method:   "POST",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "case insensitive - get matches GET",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			method:   "get",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "POST matches POST",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			method:   "POST",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "DELETE matches DELETE",
			request:  []byte("DELETE /api/users/1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			method:   "DELETE",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "PUT matches PUT",
			request:  []byte("PUT /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			method:   "PUT",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "PATCH matches PATCH",
			request:  []byte("PATCH /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			method:   "PATCH",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			method:   "GET",
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := IsMethodType(tt.request, tt.method)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("IsMethodType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSwitchMethod tests switching HTTP method
func TestSwitchMethod(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		newMethod string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:      "switch GET to POST",
			request:   []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newMethod: "POST",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("POST /api HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:      "switch POST to PUT",
			request:   []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nbody"),
			newMethod: "PUT",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("PUT /api HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:      "switch to OPTIONS",
			request:   []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newMethod: "OPTIONS",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("OPTIONS /api HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:      "nil request",
			request:   nil,
			newMethod: "POST",
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SwitchMethod(tt.request, tt.newMethod)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("SwitchMethod() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// ==================== QUERY STRING OPERATIONS TESTS ====================

// TestGetQueryString tests extracting query string
func TestGetQueryString(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "simple query string",
			request:  []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "id=123",
			wantErr:  false,
		},
		{
			name:     "multiple parameters",
			request:  []byte("GET /api?id=123&name=test&filter=active HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "id=123&name=test&filter=active",
			wantErr:  false,
		},
		{
			name:     "no query string",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "empty query string",
			request:  []byte("GET /api? HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "encoded characters",
			request:  []byte("GET /search?q=hello%20world&sort=desc HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "q=hello%20world&sort=desc",
			wantErr:  false,
		},
		{
			name:     "special characters",
			request:  []byte("GET /api?data=a%3Db%26c%3Dd HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "data=a%3Db%26c%3Dd",
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetQueryString(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("GetQueryString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestSetQueryString tests replacing query string
func TestSetQueryString(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		newQuery  string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:     "add query string",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newQuery: "id=123&name=test",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api?id=123&name=test HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:     "replace query string",
			request:  []byte("GET /api?old=value HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newQuery: "new=data",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api?new=data HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:     "empty query string removes query",
			request:  []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newQuery: "",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api HTTP/1.1\r\n")) &&
					!bytes.Contains(result, []byte("?"))
			},
			wantErr: false,
		},
		{
			name:     "preserve path",
			request:  []byte("GET /api/v2/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newQuery: "filter=active",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api/v2/users?filter=active HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:     "nil request",
			request:  nil,
			newQuery: "id=123",
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetQueryString(tt.request, tt.newQuery)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("SetQueryString() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestClearQueryString tests removing query string
func TestClearQueryString(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "remove simple query",
			request: []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api HTTP/1.1\r\n")) &&
					!bytes.Contains(result, []byte("?"))
			},
			wantErr: false,
		},
		{
			name:    "remove complex query",
			request: []byte("GET /api?id=123&name=test&filter=active HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api HTTP/1.1\r\n")) &&
					!bytes.Contains(result, []byte("?"))
			},
			wantErr: false,
		},
		{
			name:    "already no query",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "preserve path",
			request: []byte("GET /api/v2/users?page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api/v2/users HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ClearQueryString(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("ClearQueryString() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestGetURLParameter tests extracting single URL parameter.
// Uses ParseQueryParameters for query-string-only input per Burp's two-function architecture:
// - High-level: ParseQueryString expects full URL with '?'
// - Low-level: ParseQueryParameters expects query portion only (no '?')
func TestGetURLParameter(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		paramName string
		expected  string
		wantErr   bool
	}{
		{
			name:      "parameter in query - first param",
			request:   []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName: "id",
			expected:  "123", // Fixed: now uses ParseQueryParameters
			wantErr:   false,
		},
		{
			name:      "second parameter in query",
			request:   []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName: "name",
			expected:  "test", // Fixed: now uses ParseQueryParameters
			wantErr:   false,
		},
		{
			name:      "parameter not found",
			request:   []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName: "missing",
			expected:  "",
			wantErr:   false,
		},
		{
			name:      "no query string",
			request:   []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName: "id",
			expected:  "",
			wantErr:   false,
		},
		{
			name:      "empty value",
			request:   []byte("GET /api?id= HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName: "id",
			expected:  "",
			wantErr:   false,
		},
		{
			name:      "nil request",
			request:   nil,
			paramName: "id",
			expected:  "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetURLParameter(tt.request, tt.paramName)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("GetURLParameter() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestHasURLParameter tests checking URL parameter existence.
// Uses ParseQueryParameters for query-string-only input per Burp's architecture.
func TestHasURLParameter(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		paramName string
		expected  bool
		wantErr   bool
	}{
		{
			name:      "parameter exists",
			request:   []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName: "id",
			expected:  true, // Fixed: now uses ParseQueryParameters
			wantErr:   false,
		},
		{
			name:      "parameter does not exist",
			request:   []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName: "missing",
			expected:  false,
			wantErr:   false,
		},
		{
			name:      "no query string",
			request:   []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName: "id",
			expected:  false,
			wantErr:   false,
		},
		{
			name:      "nil request",
			request:   nil,
			paramName: "id",
			expected:  false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HasURLParameter(tt.request, tt.paramName)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("HasURLParameter() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetURLParametersMap tests getting all parameters as map.
// Uses ParseQueryParameters for query-string-only input per Burp's architecture.
func TestGetURLParametersMap(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected map[string]string
		wantErr  bool
	}{
		{
			name:    "simple parameters",
			request: []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: map[string]string{
				"id":   "123",
				"name": "test",
			}, // Fixed: now uses ParseQueryParameters
			wantErr: false,
		},
		{
			name:     "no parameters",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetURLParametersMap(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if len(result) != len(tt.expected) {
				t.Errorf("GetURLParametersMap() returned %d params, want %d", len(result), len(tt.expected))
				return
			}
			for key, expectedValue := range tt.expected {
				if actualValue, ok := result[key]; !ok {
					t.Errorf("GetURLParametersMap() missing key %q", key)
				} else if actualValue != expectedValue {
					t.Errorf("GetURLParametersMap()[%q] = %q, want %q", key, actualValue, expectedValue)
				}
			}
		})
	}
}

// TestSetURLParametersMap tests setting all parameters from map
func TestSetURLParametersMap(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		params    map[string]string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "set simple parameters",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			params: map[string]string{
				"id":   "123",
				"name": "test",
			},
			checkFunc: func(result []byte) bool {
				path, _ := GetPath(result)
				return (path == "/api?id=123&name=test" || path == "/api?name=test&id=123")
			},
			wantErr: false,
		},
		{
			name:    "replace parameters",
			request: []byte("GET /api?old=value HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			params: map[string]string{
				"new": "data",
			},
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("new=data")) &&
					!bytes.Contains(result, []byte("old=value"))
			},
			wantErr: false,
		},
		{
			name:    "empty map removes parameters",
			request: []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			params:  map[string]string{},
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api HTTP/1.1\r\n")) &&
					!bytes.Contains(result, []byte("?"))
			},
			wantErr: false,
		},
		{
			name:    "special characters encoded with plus",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			params: map[string]string{
				"q": "hello world",
			},
			checkFunc: func(result []byte) bool {
				// EncodeQueryValue encodes spaces as '+'
				return bytes.Contains(result, []byte("q=hello+world"))
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			params: map[string]string{
				"id": "123",
			},
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetURLParametersMap(tt.request, tt.params)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("SetURLParametersMap() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestAppendURLParameter tests appending URL parameter
func TestAppendURLParameter(t *testing.T) {
	tests := []struct {
		name       string
		request    []byte
		paramName  string
		paramValue string
		checkFunc  func([]byte) bool
		wantErr    bool
	}{
		{
			name:       "append to empty query",
			request:    []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName:  "id",
			paramValue: "123",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api?id=123 HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:       "append to existing query",
			request:    []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName:  "name",
			paramValue: "test",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("GET /api?id=123&name=test HTTP/1.1\r\n"))
			},
			wantErr: false,
		},
		{
			name:       "append with encoding (space as plus)",
			request:    []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName:  "q",
			paramValue: "hello world",
			checkFunc: func(result []byte) bool {
				// EncodeQueryValue encodes spaces as '+'
				return bytes.Contains(result, []byte("q=hello+world"))
			},
			wantErr: false,
		},
		{
			name:       "append special characters",
			request:    []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName:  "data",
			paramValue: "a=b&c",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("data=a%3Db%26c"))
			},
			wantErr: false,
		},
		{
			name:       "append empty value",
			request:    []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			paramName:  "empty",
			paramValue: "",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("empty="))
			},
			wantErr: false,
		},
		{
			name:       "nil request",
			request:    nil,
			paramName:  "id",
			paramValue: "123",
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AppendURLParameter(tt.request, tt.paramName, tt.paramValue)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("AppendURLParameter() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// ==================== BODY OPERATIONS TESTS ====================

// TestGetBody tests extracting request body
func TestGetBody(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:     "simple body",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest data"),
			expected: []byte("test data"),
			wantErr:  false,
		},
		{
			name:     "no body",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "JSON body",
			request:  []byte("POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"),
			expected: []byte("{\"key\":\"value\"}"),
			wantErr:  false,
		},
		{
			name:     "form data body",
			request:  []byte("POST /api HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=john&pass=secret"),
			expected: []byte("user=john&pass=secret"),
			wantErr:  false,
		},
		{
			name:     "multiline body",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nline1\r\nline2\r\nline3"),
			expected: []byte("line1\r\nline2\r\nline3"),
			wantErr:  false,
		},
		{
			name:     "binary data",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n\x00\x01\x02\x03"),
			expected: []byte{0x00, 0x01, 0x02, 0x03},
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetBody(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("GetBody() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestGetBodyString tests extracting body as string
func TestGetBodyString(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "simple body",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest data"),
			expected: "test data",
			wantErr:  false,
		},
		{
			name:     "no body",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "JSON body",
			request:  []byte("POST /api HTTP/1.1\r\n\r\n{\"key\":\"value\"}"),
			expected: "{\"key\":\"value\"}",
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetBodyString(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("GetBodyString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestGetBodySize tests getting body size
func TestGetBodySize(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected int
		wantErr  bool
	}{
		{
			name:     "simple body",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest data"),
			expected: 9,
			wantErr:  false,
		},
		{
			name:     "no body",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "JSON body",
			request:  []byte("POST /api HTTP/1.1\r\n\r\n{\"key\":\"value\"}"),
			expected: 15,
			wantErr:  false,
		},
		{
			name:     "form data",
			request:  []byte("POST /api HTTP/1.1\r\n\r\nuser=john&pass=secret"),
			expected: 21,
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: 0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetBodySize(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("GetBodySize() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestHasBody tests checking if request has body
func TestHasBody(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected bool
		wantErr  bool
	}{
		{
			name:     "has body",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest data"),
			expected: true,
			wantErr:  false,
		},
		{
			name:     "no body",
			request:  []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
			wantErr:  false,
		},
		{
			name:     "empty body",
			request:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
			wantErr:  false,
		},
		{
			name:     "JSON body",
			request:  []byte("POST /api HTTP/1.1\r\n\r\n{\"key\":\"value\"}"),
			expected: true,
			wantErr:  false,
		},
		{
			name:     "nil request",
			request:  nil,
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HasBody(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("HasBody() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSetBody tests replacing request body
func TestSetBody(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		newBody   []byte
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "set simple body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newBody: []byte("new data"),
			checkFunc: func(result []byte) bool {
				body, _ := GetBody(result)
				return bytes.Equal(body, []byte("new data"))
			},
			wantErr: false,
		},
		{
			name:    "replace existing body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nold data"),
			newBody: []byte("new data"),
			checkFunc: func(result []byte) bool {
				body, _ := GetBody(result)
				return bytes.Equal(body, []byte("new data"))
			},
			wantErr: false,
		},
		{
			name:    "set JSON body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newBody: []byte("{\"key\":\"value\"}"),
			checkFunc: func(result []byte) bool {
				body, _ := GetBody(result)
				return bytes.Equal(body, []byte("{\"key\":\"value\"}"))
			},
			wantErr: false,
		},
		{
			name:    "set empty body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nold data"),
			newBody: []byte{},
			checkFunc: func(result []byte) bool {
				size, _ := GetBodySize(result)
				return size == 0
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			newBody: []byte("data"),
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetBody(tt.request, tt.newBody)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("SetBody() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestSetBodyString tests replacing body with string
func TestSetBodyString(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		newBody   string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "set simple string body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newBody: "new data",
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "new data"
			},
			wantErr: false,
		},
		{
			name:    "replace with string",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nold data"),
			newBody: "new data",
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "new data"
			},
			wantErr: false,
		},
		{
			name:    "set JSON string",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			newBody: "{\"key\":\"value\"}",
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "{\"key\":\"value\"}"
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			newBody: "data",
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetBodyString(tt.request, tt.newBody)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("SetBodyString() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestClearBody tests removing request body
func TestClearBody(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "clear simple body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest data"),
			checkFunc: func(result []byte) bool {
				hasBody, _ := HasBody(result)
				return !hasBody
			},
			wantErr: false,
		},
		{
			name:    "clear JSON body",
			request: []byte("POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"),
			checkFunc: func(result []byte) bool {
				hasBody, _ := HasBody(result)
				hasContentType := bytes.Contains(result, []byte("Content-Type"))
				hasContentLength := bytes.Contains(result, []byte("Content-Length"))
				return !hasBody && !hasContentType && !hasContentLength
			},
			wantErr: false,
		},
		{
			name:    "clear already empty",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			checkFunc: func(result []byte) bool {
				hasBody, _ := HasBody(result)
				return !hasBody
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ClearBody(tt.request)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("ClearBody() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestAppendBody tests appending to request body
func TestAppendBody(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		appendStr []byte
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:      "append to existing body",
			request:   []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\noriginal"),
			appendStr: []byte(" appended"),
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "original appended"
			},
			wantErr: false,
		},
		{
			name:      "append to empty body",
			request:   []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			appendStr: []byte("new data"),
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "new data"
			},
			wantErr: false,
		},
		{
			name:      "append form parameter",
			request:   []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nuser=john"),
			appendStr: []byte("&pass=secret"),
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "user=john&pass=secret"
			},
			wantErr: false,
		},
		{
			name:      "append empty data",
			request:   []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\noriginal"),
			appendStr: []byte{},
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "original"
			},
			wantErr: false,
		},
		{
			name:      "nil request",
			request:   nil,
			appendStr: []byte("data"),
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AppendBody(tt.request, tt.appendStr)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("AppendBody() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// TestPrependBody tests prepending to request body
func TestPrependBody(t *testing.T) {
	tests := []struct {
		name       string
		request    []byte
		prependStr []byte
		checkFunc  func([]byte) bool
		wantErr    bool
	}{
		{
			name:       "prepend to existing body",
			request:    []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\noriginal"),
			prependStr: []byte("prepended "),
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "prepended original"
			},
			wantErr: false,
		},
		{
			name:       "prepend to empty body",
			request:    []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			prependStr: []byte("new data"),
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "new data"
			},
			wantErr: false,
		},
		{
			name:       "prepend prefix",
			request:    []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ndata"),
			prependStr: []byte("prefix_"),
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "prefix_data"
			},
			wantErr: false,
		},
		{
			name:       "prepend empty data",
			request:    []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\noriginal"),
			prependStr: []byte{},
			checkFunc: func(result []byte) bool {
				body, _ := GetBodyString(result)
				return body == "original"
			},
			wantErr: false,
		},
		{
			name:       "nil request",
			request:    nil,
			prependStr: []byte("data"),
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PrependBody(tt.request, tt.prependStr)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("PrependBody() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}

// ==================== INTEGRATION TESTS ====================

// TestRequestBuilderIntegration tests complex scenarios combining multiple operations
func TestRequestBuilderIntegration(t *testing.T) {
	t.Run("complete request modification workflow", func(t *testing.T) {
		// Start with GET request
		request := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")

		// Change to POST
		request, err := SetMethod(request, "POST")
		if err != nil {
			t.Fatalf("SetMethod failed: %v", err)
		}

		// Add query parameters
		request, err = AppendURLParameter(request, "id", "123")
		if err != nil {
			t.Fatalf("AppendURLParameter failed: %v", err)
		}

		// Add body
		request, err = SetBodyString(request, "{\"action\":\"update\"}")
		if err != nil {
			t.Fatalf("SetBodyString failed: %v", err)
		}

		// Verify final state
		method, _ := GetMethod(request)
		if method != "POST" {
			t.Errorf("Method = %q, want POST", method)
		}

		// Verify query string exists
		query, _ := GetQueryString(request)
		if query != "id=123" {
			t.Errorf("Query = %q, want id=123", query)
		}

		// Verify parameter exists using HasURLParameter (now fixed)
		hasID, _ := HasURLParameter(request, "id")
		if !hasID {
			t.Error("HasURLParameter(id) = false, want true")
		}

		body, _ := GetBodyString(request)
		if body != "{\"action\":\"update\"}" {
			t.Errorf("Body = %q, want {\"action\":\"update\"}", body)
		}
	})

	t.Run("query parameter manipulation workflow", func(t *testing.T) {
		request := []byte("GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

		// Get all parameters - now works correctly
		params, err := GetURLParametersMap(request)
		if err != nil {
			t.Fatalf("GetURLParametersMap failed: %v", err)
		}

		// Verify we got the expected parameters
		if len(params) != 2 {
			t.Errorf("Got %d params, want 2", len(params))
		}
		if params["q"] != "test" {
			t.Errorf("params[q] = %q, want test", params["q"])
		}
		if params["page"] != "1" {
			t.Errorf("params[page] = %q, want 1", params["page"])
		}

		// Modify params
		params = map[string]string{"page": "2", "sort": "desc"}

		// Set back with new params
		request, err = SetURLParametersMap(request, params)
		if err != nil {
			t.Fatalf("SetURLParametersMap failed: %v", err)
		}

		// Verify query string was updated
		query, _ := GetQueryString(request)
		validQuery := query == "page=2&sort=desc" || query == "sort=desc&page=2"
		if !validQuery {
			t.Errorf("query = %q, want params in some order", query)
		}

		// Verify using GetURLParameter (now fixed)
		pageVal, _ := GetURLParameter(request, "page")
		if pageVal != "2" {
			t.Errorf("GetURLParameter(page) = %q, want 2", pageVal)
		}
		sortVal, _ := GetURLParameter(request, "sort")
		if sortVal != "desc" {
			t.Errorf("GetURLParameter(sort) = %q, want desc", sortVal)
		}
	})

	t.Run("path manipulation preserving components", func(t *testing.T) {
		request := []byte("GET /api/v1/users?filter=active HTTP/1.1\r\nHost: example.com\r\n\r\n")

		// Change path only
		request, err := SetPathOnly(request, "/api/v2/users")
		if err != nil {
			t.Fatalf("SetPathOnly failed: %v", err)
		}

		// Verify path changed but query preserved
		pathOnly, _ := GetPathOnly(request)
		if pathOnly != "/api/v2/users" {
			t.Errorf("pathOnly = %q, want /api/v2/users", pathOnly)
		}

		// Verify query is still there (check raw query string since GetURLParameter is buggy)
		query, _ := GetQueryString(request)
		if query != "filter=active" {
			t.Errorf("query = %q, want filter=active", query)
		}
	})
}

// ==================== BENCHMARKS ====================

func BenchmarkGetMethod(b *testing.B) {
	request := []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetMethod(request)
	}
}

func BenchmarkGetPath(b *testing.B) {
	request := []byte("GET /api/v2/users?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetPath(request)
	}
}

func BenchmarkSetMethod(b *testing.B) {
	request := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SetMethod(request, "POST")
	}
}

func BenchmarkGetQueryString(b *testing.B) {
	request := []byte("GET /api?id=123&name=test&filter=active HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetQueryString(request)
	}
}

func BenchmarkGetURLParameter(b *testing.B) {
	request := []byte("GET /api?id=123&name=test&filter=active HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetURLParameter(request, "name")
	}
}

func BenchmarkGetURLParametersMap(b *testing.B) {
	request := []byte("GET /api?id=123&name=test&filter=active&sort=desc HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetURLParametersMap(request)
	}
}

func BenchmarkSetURLParametersMap(b *testing.B) {
	request := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	params := map[string]string{
		"id":     "123",
		"name":   "test",
		"filter": "active",
		"sort":   "desc",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SetURLParametersMap(request, params)
	}
}

func BenchmarkAppendURLParameter(b *testing.B) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AppendURLParameter(request, "name", "test")
	}
}

func BenchmarkGetBody(b *testing.B) {
	request := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{\"key\":\"value\",\"data\":\"test\"}")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetBody(request)
	}
}

func BenchmarkSetBody(b *testing.B) {
	request := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	body := []byte("{\"key\":\"value\"}")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SetBody(request, body)
	}
}

func BenchmarkAppendBody(b *testing.B) {
	request := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nuser=john")
	appendData := []byte("&pass=secret")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AppendBody(request, appendData)
	}
}

// ==================== NEW UTILITY FUNCTION TESTS ====================

// TestGetExtension tests extracting file extension from request path
func TestGetExtension(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "JSON extension",
			request:  []byte("GET /api/file.json HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: ".json",
			wantErr:  false,
		},
		{
			name:     "HTML extension",
			request:  []byte("GET /page.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: ".html",
			wantErr:  false,
		},
		{
			name:     "Extension with query string",
			request:  []byte("GET /api/file.json?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: ".json",
			wantErr:  false,
		},
		{
			name:     "No extension",
			request:  []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "Root path",
			request:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "Dot in directory path",
			request:  []byte("GET /api.v2/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "Dot in directory and file",
			request:  []byte("GET /api.v2/users.json HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: ".json",
			wantErr:  false,
		},
		{
			name:     "PHP extension",
			request:  []byte("GET /index.php HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: ".php",
			wantErr:  false,
		},
		{
			name:     "Multiple dots",
			request:  []byte("GET /file.backup.tar.gz HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: ".gz",
			wantErr:  false,
		},
		{
			name:     "Nil request",
			request:  nil,
			expected: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetExtension(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetExtension() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("GetExtension() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestAppendToPath tests appending segments to request path
func TestAppendToPath(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		segment   string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "Append to simple path",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			segment: "/extra",
			checkFunc: func(result []byte) bool {
				path, _ := GetPath(result)
				return path == "/api/extra"
			},
			wantErr: false,
		},
		{
			name:    "Append preserving query string",
			request: []byte("GET /api?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			segment: "/extra",
			checkFunc: func(result []byte) bool {
				path, _ := GetPath(result)
				return path == "/api/extra?id=1"
			},
			wantErr: false,
		},
		{
			name:    "Append to root path",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			segment: "api",
			checkFunc: func(result []byte) bool {
				path, _ := GetPath(result)
				return path == "/api"
			},
			wantErr: false,
		},
		{
			name:    "Append empty segment",
			request: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			segment: "",
			checkFunc: func(result []byte) bool {
				path, _ := GetPath(result)
				return path == "/api"
			},
			wantErr: false,
		},
		{
			name:    "Append with body preserved",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\nbody content"),
			segment: "/v2",
			checkFunc: func(result []byte) bool {
				path, _ := GetPath(result)
				body, _ := GetBodyString(result)
				return path == "/api/v2" && body == "body content"
			},
			wantErr: false,
		},
		{
			name:    "Append to path with extension",
			request: []byte("GET /file.json HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			segment: ".bak",
			checkFunc: func(result []byte) bool {
				path, _ := GetPath(result)
				return path == "/file.json.bak"
			},
			wantErr: false,
		},
		{
			name:    "Nil request",
			request: nil,
			segment: "/extra",
			checkFunc: func(result []byte) bool {
				return result == nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AppendToPath(tt.request, tt.segment)
			if (err != nil) != tt.wantErr {
				t.Errorf("AppendToPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.checkFunc(result) {
				t.Errorf("AppendToPath() failed validation\nResult:\n%s", string(result))
			}
		})
	}
}
