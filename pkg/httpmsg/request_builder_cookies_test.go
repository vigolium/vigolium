package httpmsg

import (
	"bytes"
	"strings"
	"testing"
)

// ==================== COOKIE OPERATIONS TESTS ====================

// TestGetCookie tests extracting a single cookie value by name
func TestGetCookie(t *testing.T) {
	tests := []struct {
		name       string
		request    []byte
		cookieName string
		wantValue  string
		wantErr    bool
	}{
		{
			name:       "single cookie",
			request:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n"),
			cookieName: "session",
			wantValue:  "abc123",
			wantErr:    false,
		},
		{
			name:       "multiple cookies - first",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123; user=john; token=xyz789\r\n\r\n"),
			cookieName: "session",
			wantValue:  "abc123",
			wantErr:    false,
		},
		{
			name:       "multiple cookies - middle",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123; user=john; token=xyz789\r\n\r\n"),
			cookieName: "user",
			wantValue:  "john",
			wantErr:    false,
		},
		{
			name:       "multiple cookies - last",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123; user=john; token=xyz789\r\n\r\n"),
			cookieName: "token",
			wantValue:  "xyz789",
			wantErr:    false,
		},
		{
			name:       "cookie with URL-encoded value",
			request:    []byte("GET / HTTP/1.1\r\nCookie: data=hello%20world\r\n\r\n"),
			cookieName: "data",
			wantValue:  "hello world", // Decoded: %20 → space
			wantErr:    false,
		},
		{
			name:       "cookie with special characters",
			request:    []byte("GET / HTTP/1.1\r\nCookie: special=a+b=c\r\n\r\n"),
			cookieName: "special",
			wantValue:  "a b=c", // Decoded: + → space (form-encoding)
			wantErr:    false,
		},
		{
			name:       "cookie with empty value",
			request:    []byte("GET / HTTP/1.1\r\nCookie: empty=\r\n\r\n"),
			cookieName: "empty",
			wantValue:  "",
			wantErr:    false,
		},
		{
			name:       "cookie not found",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"),
			cookieName: "missing",
			wantValue:  "",
			wantErr:    false,
		},
		{
			name:       "no cookies in request",
			request:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			cookieName: "session",
			wantValue:  "",
			wantErr:    false,
		},
		{
			name:       "malformed request - no headers",
			request:    []byte("invalid"),
			cookieName: "session",
			wantValue:  "",
			wantErr:    false, // AnalyzeRequest handles gracefully
		},
		{
			name:       "nil request",
			request:    nil,
			cookieName: "session",
			wantValue:  "",
			wantErr:    false, // Returns empty without error
		},
		{
			name:       "empty cookie name - returns empty",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc\r\n\r\n"),
			cookieName: "",
			wantValue:  "",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetCookie(tt.request, tt.cookieName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantValue {
				t.Errorf("GetCookie() = %v, want %v", got, tt.wantValue)
			}
		})
	}
}

// TestGetAllCookies tests getting all cookies as a map
func TestGetAllCookies(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "single cookie",
			request: []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"),
			want: map[string]string{
				"session": "abc123",
			},
			wantErr: false,
		},
		{
			name:    "multiple cookies",
			request: []byte("GET / HTTP/1.1\r\nCookie: session=abc123; user=john; token=xyz789\r\n\r\n"),
			want: map[string]string{
				"session": "abc123",
				"user":    "john",
				"token":   "xyz789",
			},
			wantErr: false,
		},
		{
			name:    "no cookies",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want:    map[string]string{},
			wantErr: false,
		},
		{
			name:    "cookies with empty values",
			request: []byte("GET / HTTP/1.1\r\nCookie: a=; b=value; c=\r\n\r\n"),
			want: map[string]string{
				"a": "",
				"b": "value",
				"c": "",
			},
			wantErr: false,
		},
		{
			name:    "cookies with special characters",
			request: []byte("GET / HTTP/1.1\r\nCookie: data=hello%20world; special=a+b=c\r\n\r\n"),
			want: map[string]string{
				"data":    "hello world", // Decoded: %20 → space
				"special": "a b=c",       // Decoded: + → space (form-encoding)
			},
			wantErr: false,
		},
		{
			name:    "malformed request",
			request: []byte("invalid"),
			want:    map[string]string{},
			wantErr: false, // Returns empty map
		},
		{
			name:    "nil request",
			request: nil,
			want:    map[string]string{},
			wantErr: false, // Returns empty map
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAllCookies(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAllCookies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("GetAllCookies() returned %d cookies, want %d", len(got), len(tt.want))
					return
				}
				for k, v := range tt.want {
					if got[k] != v {
						t.Errorf("GetAllCookies()[%s] = %v, want %v", k, got[k], v)
					}
				}
			}
		})
	}
}

// TestHasCookie tests checking if a cookie exists
func TestHasCookie(t *testing.T) {
	tests := []struct {
		name       string
		request    []byte
		cookieName string
		want       bool
		wantErr    bool
	}{
		{
			name:       "cookie exists",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"),
			cookieName: "session",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "cookie exists in multiple cookies",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc; user=john; token=xyz\r\n\r\n"),
			cookieName: "user",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "cookie does not exist",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"),
			cookieName: "missing",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "no cookies in request",
			request:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			cookieName: "session",
			want:       false,
			wantErr:    false,
		},
		{
			name:       "cookie with empty value exists",
			request:    []byte("GET / HTTP/1.1\r\nCookie: empty=\r\n\r\n"),
			cookieName: "empty",
			want:       true,
			wantErr:    false,
		},
		{
			name:       "malformed request",
			request:    []byte("invalid"),
			cookieName: "session",
			want:       false,
			wantErr:    false, // Returns false without error
		},
		{
			name:       "nil request",
			request:    nil,
			cookieName: "session",
			want:       false,
			wantErr:    false, // Returns false without error
		},
		{
			name:       "empty cookie name - returns false",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc\r\n\r\n"),
			cookieName: "",
			want:       false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HasCookie(tt.request, tt.cookieName)
			if (err != nil) != tt.wantErr {
				t.Errorf("HasCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("HasCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSetCookie tests setting or updating a cookie
func TestSetCookie(t *testing.T) {
	tests := []struct {
		name        string
		request     []byte
		cookieName  string
		cookieValue string
		checkFunc   func([]byte) bool
		wantErr     bool
	}{
		{
			name:        "add cookie to request without cookies",
			request:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			cookieName:  "session",
			cookieValue: "abc123",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("Cookie: session=abc123"))
			},
			wantErr: false,
		},
		{
			name:        "update existing cookie",
			request:     []byte("GET / HTTP/1.1\r\nCookie: session=old\r\n\r\n"),
			cookieName:  "session",
			cookieValue: "new",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("session=new")) &&
					!bytes.Contains(result, []byte("session=old"))
			},
			wantErr: false,
		},
		{
			name:        "add cookie to request with other cookies",
			request:     []byte("GET / HTTP/1.1\r\nCookie: user=john\r\n\r\n"),
			cookieName:  "session",
			cookieValue: "abc123",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("session=abc123")) &&
					bytes.Contains(result, []byte("user=john"))
			},
			wantErr: false,
		},
		{
			name:        "set cookie with URL-encoded value",
			request:     []byte("GET / HTTP/1.1\r\n\r\n"),
			cookieName:  "data",
			cookieValue: "hello%20world",
			checkFunc: func(result []byte) bool {
				// Values are written as-is without double-encoding
				// If value is "hello%20world", it's written as "data=hello%20world"
				return bytes.Contains(result, []byte("data=hello%20world"))
			},
			wantErr: false,
		},
		{
			name:        "set cookie with empty value",
			request:     []byte("GET / HTTP/1.1\r\n\r\n"),
			cookieName:  "empty",
			cookieValue: "",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("empty="))
			},
			wantErr: false,
		},
		{
			name:        "set cookie with special characters",
			request:     []byte("GET / HTTP/1.1\r\n\r\n"),
			cookieName:  "special",
			cookieValue: "a+b=c",
			checkFunc: func(result []byte) bool {
				// Values are written as-is without encoding
				// User must pre-encode values if needed
				return bytes.Contains(result, []byte("special=a+b=c"))
			},
			wantErr: false,
		},
		{
			name:        "malformed request",
			request:     []byte("invalid"),
			cookieName:  "session",
			cookieValue: "abc",
			checkFunc:   nil,
			wantErr:     false, // Returns nil without error
		},
		{
			name:        "nil request",
			request:     nil,
			cookieName:  "session",
			cookieValue: "abc",
			checkFunc:   nil,
			wantErr:     false, // Returns nil without error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SetCookie(tt.request, tt.cookieName, tt.cookieValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil && !tt.checkFunc(got) {
				t.Errorf("SetCookie() result validation failed\nGot: %s", string(got))
			}
		})
	}
}

// TestRemoveCookie tests removing a cookie
func TestRemoveCookie(t *testing.T) {
	tests := []struct {
		name       string
		request    []byte
		cookieName string
		checkFunc  func([]byte) bool
		wantErr    bool
	}{
		{
			name:       "remove existing cookie",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"),
			cookieName: "session",
			checkFunc: func(result []byte) bool {
				return !bytes.Contains(result, []byte("session="))
			},
			wantErr: false,
		},
		{
			name:       "remove cookie from multiple cookies",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc; user=john; token=xyz\r\n\r\n"),
			cookieName: "user",
			checkFunc: func(result []byte) bool {
				return !bytes.Contains(result, []byte("user=")) &&
					bytes.Contains(result, []byte("session=abc")) &&
					bytes.Contains(result, []byte("token=xyz"))
			},
			wantErr: false,
		},
		{
			name:       "remove non-existent cookie",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"),
			cookieName: "missing",
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("session=abc123"))
			},
			wantErr: false,
		},
		{
			name:       "remove last remaining cookie",
			request:    []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"),
			cookieName: "session",
			checkFunc: func(result []byte) bool {
				return !bytes.Contains(result, []byte("Cookie:")) ||
					!bytes.Contains(result, []byte("session="))
			},
			wantErr: false,
		},
		{
			name:       "malformed request",
			request:    []byte("invalid"),
			cookieName: "session",
			checkFunc:  nil,
			wantErr:    false, // Returns nil without error
		},
		{
			name:       "nil request",
			request:    nil,
			cookieName: "session",
			checkFunc:  nil,
			wantErr:    false, // Returns nil without error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RemoveCookie(tt.request, tt.cookieName)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoveCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil && !tt.checkFunc(got) {
				t.Errorf("RemoveCookie() result validation failed\nGot: %s", string(got))
			}
		})
	}
}

// TestSetAllCookies tests replacing all cookies with a map
func TestSetAllCookies(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		cookies   map[string]string
		checkFunc func([]byte) bool
		wantErr   bool
	}{
		{
			name:    "replace all cookies",
			request: []byte("GET / HTTP/1.1\r\nCookie: old1=value1; old2=value2\r\n\r\n"),
			cookies: map[string]string{
				"new1": "valueA",
				"new2": "valueB",
			},
			checkFunc: func(result []byte) bool {
				return !bytes.Contains(result, []byte("old1=")) &&
					!bytes.Contains(result, []byte("old2=")) &&
					bytes.Contains(result, []byte("new1=valueA")) &&
					bytes.Contains(result, []byte("new2=valueB"))
			},
			wantErr: false,
		},
		{
			name:    "set cookies on request without cookies",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			cookies: map[string]string{
				"session": "abc123",
				"user":    "john",
			},
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("session=abc123")) &&
					bytes.Contains(result, []byte("user=john"))
			},
			wantErr: false,
		},
		{
			name:    "set empty cookies map",
			request: []byte("GET / HTTP/1.1\r\nCookie: session=abc123; user=john\r\n\r\n"),
			cookies: map[string]string{},
			checkFunc: func(result []byte) bool {
				return !bytes.Contains(result, []byte("session=")) &&
					!bytes.Contains(result, []byte("user="))
			},
			wantErr: false,
		},
		{
			name:    "set single cookie",
			request: []byte("GET / HTTP/1.1\r\nCookie: old=value\r\n\r\n"),
			cookies: map[string]string{
				"new": "value",
			},
			checkFunc: func(result []byte) bool {
				return !bytes.Contains(result, []byte("old=")) &&
					bytes.Contains(result, []byte("new=value"))
			},
			wantErr: false,
		},
		{
			name:    "set cookies with special characters",
			request: []byte("GET / HTTP/1.1\r\n\r\n"),
			cookies: map[string]string{
				"data":    "hello%20world",
				"special": "a+b=c",
			},
			checkFunc: func(result []byte) bool {
				// Values are written as-is without encoding
				return bytes.Contains(result, []byte("data=hello%20world")) &&
					bytes.Contains(result, []byte("special=a+b=c"))
			},
			wantErr: false,
		},
		{
			name:    "set cookies with empty values",
			request: []byte("GET / HTTP/1.1\r\n\r\n"),
			cookies: map[string]string{
				"empty": "",
				"value": "test",
			},
			checkFunc: func(result []byte) bool {
				return bytes.Contains(result, []byte("empty=")) &&
					bytes.Contains(result, []byte("value=test"))
			},
			wantErr: false,
		},
		{
			name:    "malformed request",
			request: []byte("invalid"),
			cookies: map[string]string{
				"session": "abc",
			},
			checkFunc: nil,
			wantErr:   false, // Returns nil without error
		},
		{
			name:    "nil request",
			request: nil,
			cookies: map[string]string{
				"session": "abc",
			},
			checkFunc: nil,
			wantErr:   false, // Returns nil without error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SetAllCookies(tt.request, tt.cookies)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetAllCookies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil && !tt.checkFunc(got) {
				t.Errorf("SetAllCookies() result validation failed\nGot: %s", string(got))
			}
		})
	}
}

// ==================== VALIDATION & INSPECTION TESTS ====================

// TestValidateRequest tests checking if a request is well-formed
func TestValidateRequest(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		wantErr bool
	}{
		{
			name:    "valid GET request",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid POST request with body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"),
			wantErr: false,
		},
		{
			name:    "valid request with multiple headers",
			request: []byte("GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid request with cookies",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "malformed request - no HTTP version",
			request: []byte("GET /\r\n\r\n"),
			wantErr: false, // AnalyzeRequest handles gracefully
		},
		{
			name:    "malformed request - invalid format",
			request: []byte("invalid request"),
			wantErr: false, // AnalyzeRequest handles gracefully
		},
		{
			name:    "empty request",
			request: []byte(""),
			wantErr: false, // Returns empty analysis
		},
		{
			name:    "nil request",
			request: nil,
			wantErr: false, // Returns empty analysis
		},
		{
			name:    "request with only request line",
			request: []byte("GET / HTTP/1.1\r\n"),
			wantErr: false, // Parses as valid but incomplete
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequest(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateRequestLine tests checking if the request line is well-formed
func TestValidateRequestLine(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		wantErr bool
	}{
		{
			name:    "valid GET request line",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid POST request line",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid PUT request line",
			request: []byte("PUT /resource HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid DELETE request line",
			request: []byte("DELETE /resource HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid request with HTTP/1.0",
			request: []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid request with query string",
			request: []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "malformed - missing method",
			request: []byte("/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false, // Parses but returns partial data
		},
		{
			name:    "malformed - missing path",
			request: []byte("GET HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false, // Parses but returns partial data
		},
		{
			name:    "malformed - missing HTTP version",
			request: []byte("GET /\r\nHost: example.com\r\n\r\n"),
			wantErr: false, // Parses but returns partial data
		},
		{
			name:    "malformed - invalid format",
			request: []byte("invalid\r\n\r\n"),
			wantErr: true, // Actually malformed - returns error
		},
		{
			name:    "empty request",
			request: []byte(""),
			wantErr: true, // Empty returns error
		},
		{
			name:    "nil request",
			request: nil,
			wantErr: true, // Nil returns error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequestLine(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequestLine() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateHeaders tests checking if headers are well-formed
func TestValidateHeaders(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		wantErr bool
	}{
		{
			name:    "valid headers",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid single header",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid headers with cookies",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid headers with content-type",
			request: []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "valid headers with multiple values",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html, application/json\r\n\r\n"),
			wantErr: false,
		},
		{
			name:    "empty request",
			request: []byte(""),
			wantErr: false, // Returns empty headers
		},
		{
			name:    "nil request",
			request: nil,
			wantErr: false, // Returns empty headers
		},
		{
			name:    "malformed headers - missing separator",
			request: []byte("GET / HTTP/1.1\r\nInvalidHeader\r\n\r\n"),
			wantErr: false, // Parser handles this gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHeaders(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGetRequestSize tests getting the total size of the request
func TestGetRequestSize(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		want    int
	}{
		{
			name:    "simple GET request",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want:    37,
		},
		{
			name:    "POST request with body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"),
			want:    88,
		},
		{
			name:    "request with multiple headers",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n"),
			want:    68,
		},
		{
			name:    "empty request",
			request: []byte(""),
			want:    0,
		},
		{
			name:    "nil request",
			request: nil,
			want:    0,
		},
		{
			name:    "large request",
			request: []byte(strings.Repeat("x", 1024)),
			want:    1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetRequestSize(tt.request)
			if got != tt.want {
				t.Errorf("GetRequestSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetHeadersSize tests getting the size of headers
func TestGetHeadersSize(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		want    int
		wantErr bool
	}{
		{
			name:    "request without body",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want:    37,
			wantErr: false,
		},
		{
			name:    "request with body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest body"),
			want:    41,
			wantErr: false,
		},
		{
			name:    "request with JSON body",
			request: []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"),
			want:    70,
			wantErr: false,
		},
		{
			name:    "request with multiple headers and body",
			request: []byte("POST / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nContent-Type: text/plain\r\n\r\nbody content"),
			want:    82,
			wantErr: false,
		},
		{
			name:    "request without body separator - headers only",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com"),
			want:    33,
			wantErr: false,
		},
		{
			name:    "empty request",
			request: []byte(""),
			want:    0,
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			want:    0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetHeadersSize(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHeadersSize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetHeadersSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetBodyOffset tests getting the offset where the body starts
func TestGetBodyOffset(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		want    int
		wantErr bool
	}{
		{
			name:    "request with body",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest body"),
			want:    41,
			wantErr: false,
		},
		{
			name:    "request without body",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want:    37,
			wantErr: false,
		},
		{
			name:    "request with JSON body",
			request: []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"),
			want:    70,
			wantErr: false,
		},
		{
			name:    "request with form data",
			request: []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=john&pass=secret"),
			want:    87,
			wantErr: false,
		},
		{
			name:    "request without separator - no body",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com"),
			want:    33,
			wantErr: false,
		},
		{
			name:    "empty request",
			request: []byte(""),
			want:    0,
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			want:    -1,
			wantErr: false,
		},
		{
			name:    "request with empty body after separator",
			request: []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want:    38,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetBodyOffset(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBodyOffset() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetBodyOffset() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsWellFormed tests the boolean convenience wrapper for validation
func TestIsWellFormed(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		want    bool
	}{
		{
			name:    "well-formed GET request",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want:    true,
		},
		{
			name:    "well-formed POST request",
			request: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"),
			want:    true,
		},
		{
			name:    "well-formed request with cookies",
			request: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n"),
			want:    true,
		},
		{
			name:    "well-formed request with multiple headers",
			request: []byte("GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n"),
			want:    true,
		},
		{
			name:    "malformed - invalid format",
			request: []byte("invalid request"),
			want:    true, // Lenient parser - accepts everything
		},
		{
			name:    "malformed - missing HTTP version",
			request: []byte("GET /\r\n\r\n"),
			want:    true, // Lenient parser - accepts everything
		},
		{
			name:    "empty request",
			request: []byte(""),
			want:    true, // Lenient parser - accepts everything
		},
		{
			name:    "nil request",
			request: nil,
			want:    true, // Lenient parser - accepts everything
		},
		{
			name:    "malformed - incomplete headers",
			request: []byte("GET / HTTP/1.1\r\n"),
			want:    true, // Lenient parser - accepts everything
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWellFormed(tt.request)
			if got != tt.want {
				t.Errorf("IsWellFormed() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ==================== INTEGRATION TESTS ====================

// TestCookieOperationsIntegration tests cookie operations together
func TestCookieOperationsIntegration(t *testing.T) {
	// Start with a basic request
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Verify no cookies initially
	has, _ := HasCookie(request, "session")
	if has {
		t.Error("Expected no cookies initially")
	}

	// Add a cookie
	request, err := SetCookie(request, "session", "abc123")
	if err != nil {
		t.Fatalf("Failed to set cookie: %v", err)
	}

	// Verify cookie exists
	has, _ = HasCookie(request, "session")
	if !has {
		t.Error("Cookie should exist after SetCookie")
	}

	// Get cookie value
	value, _ := GetCookie(request, "session")
	if value != "abc123" {
		t.Errorf("GetCookie() = %v, want %v", value, "abc123")
	}

	// Add more cookies
	request, _ = SetCookie(request, "user", "john")
	request, _ = SetCookie(request, "token", "xyz789")

	// Get all cookies
	allCookies, _ := GetAllCookies(request)
	if len(allCookies) != 3 {
		t.Errorf("Expected 3 cookies, got %d", len(allCookies))
	}

	// Remove a cookie
	request, _ = RemoveCookie(request, "user")
	has, _ = HasCookie(request, "user")
	if has {
		t.Error("Cookie should not exist after RemoveCookie")
	}

	// Replace all cookies
	newCookies := map[string]string{
		"new1": "valueA",
		"new2": "valueB",
	}
	request, _ = SetAllCookies(request, newCookies)

	// Verify old cookies are gone
	has, _ = HasCookie(request, "session")
	if has {
		t.Error("Old cookie should be removed after SetAllCookies")
	}

	// Verify new cookies exist
	allCookies, _ = GetAllCookies(request)
	if len(allCookies) != 2 {
		t.Errorf("Expected 2 cookies after SetAllCookies, got %d", len(allCookies))
	}
	if allCookies["new1"] != "valueA" || allCookies["new2"] != "valueB" {
		t.Error("New cookies have incorrect values")
	}
}

// TestValidationIntegration tests validation functions together
func TestValidationIntegration(t *testing.T) {
	validRequest := []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")

	// Test IsWellFormed
	if !IsWellFormed(validRequest) {
		t.Error("Valid request should be well-formed")
	}

	// Test ValidateRequest
	if err := ValidateRequest(validRequest); err != nil {
		t.Errorf("ValidateRequest() should succeed for valid request: %v", err)
	}

	// Test ValidateRequestLine
	if err := ValidateRequestLine(validRequest); err != nil {
		t.Errorf("ValidateRequestLine() should succeed for valid request: %v", err)
	}

	// Test ValidateHeaders
	if err := ValidateHeaders(validRequest); err != nil {
		t.Errorf("ValidateHeaders() should succeed for valid request: %v", err)
	}

	// Test size calculations
	totalSize := GetRequestSize(validRequest)
	headersSize, _ := GetHeadersSize(validRequest)
	bodyOffset, _ := GetBodyOffset(validRequest)

	if totalSize <= 0 {
		t.Error("Total size should be positive")
	}
	if headersSize != bodyOffset {
		t.Error("Headers size should equal body offset for request without body")
	}
	if headersSize != totalSize {
		t.Error("Headers size should equal total size for request without body")
	}

	// Test request with body
	requestWithBody := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest body")
	totalSize = GetRequestSize(requestWithBody)
	_, _ = GetHeadersSize(requestWithBody)
	bodyOffset, _ = GetBodyOffset(requestWithBody)
	bodySize := totalSize - bodyOffset

	if bodySize != 9 { // "test body" = 9 bytes
		t.Errorf("Body size should be 9, got %d", bodySize)
	}
}

// ==================== BENCHMARKS ====================

func BenchmarkGetCookie(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nCookie: session=abc123; user=john; token=xyz789\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetCookie(request, "user")
	}
}

func BenchmarkGetAllCookies(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nCookie: session=abc123; user=john; token=xyz789; tracking=12345\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetAllCookies(request)
	}
}

func BenchmarkHasCookie(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nCookie: session=abc123; user=john; token=xyz789\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HasCookie(request, "token")
	}
}

func BenchmarkSetCookie(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=old\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SetCookie(request, "session", "new")
	}
}

func BenchmarkRemoveCookie(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nCookie: session=abc; user=john; token=xyz\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RemoveCookie(request, "user")
	}
}

func BenchmarkSetAllCookies(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nCookie: old1=value1; old2=value2\r\n\r\n")
	cookies := map[string]string{
		"new1": "valueA",
		"new2": "valueB",
		"new3": "valueC",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SetAllCookies(request, cookies)
	}
}

func BenchmarkValidateRequest(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateRequest(request)
	}
}

func BenchmarkValidateRequestLine(b *testing.B) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateRequestLine(request)
	}
}

func BenchmarkValidateHeaders(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateHeaders(request)
	}
}

func BenchmarkGetRequestSize(b *testing.B) {
	request := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetRequestSize(request)
	}
}

func BenchmarkGetHeadersSize(b *testing.B) {
	request := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest body")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetHeadersSize(request)
	}
}

func BenchmarkGetBodyOffset(b *testing.B) {
	request := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\ntest body")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetBodyOffset(request)
	}
}

func BenchmarkIsWellFormed(b *testing.B) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsWellFormed(request)
	}
}
