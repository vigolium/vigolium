package httpmsg

import (
	"testing"
)

// TestParseURLEncodedBody tests basic URL-encoded body parameter parsing
func TestParseURLEncodedBody(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected int // number of parameters
		checks   []paramCheck
	}{
		{
			name: "simple POST with URL-encoded body",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 13\r\n" +
				"\r\n" +
				"name=John&age=30"),
			expected: 2,
			checks: []paramCheck{
				{name: "name", value: "John", nameStart: 88, nameEnd: 92, valueStart: 93, valueEnd: 97},
				{name: "age", value: "30", nameStart: 98, nameEnd: 101, valueStart: 102, valueEnd: 104},
			},
		},
		{
			name: "POST with multiple parameters",
			request: []byte("POST /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"username=admin&password=secret&remember=on"),
			expected: 3,
			checks: []paramCheck{
				{name: "username", value: "admin", nameStart: 90, nameEnd: 98, valueStart: 99, valueEnd: 104},
				{name: "password", value: "secret", nameStart: 105, nameEnd: 113, valueStart: 114, valueEnd: 120},
				{name: "remember", value: "on", nameStart: 121, nameEnd: 129, valueStart: 130, valueEnd: 132},
			},
		},
		{
			name: "POST with URL-encoded values",
			request: []byte("POST /submit HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"name=John%20Doe&city=New%20York"),
			expected: 2,
			checks: []paramCheck{
				{name: "name", value: "John Doe", nameStart: 74, nameEnd: 78, valueStart: 79, valueEnd: 89},
				{name: "city", value: "New York", nameStart: 90, nameEnd: 94, valueStart: 95, valueEnd: 105},
			},
		},
		{
			name: "POST with empty values",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"key1=&key2=value&key3="),
			expected: 3,
			checks: []paramCheck{
				{name: "key1", value: "", nameStart: 68, nameEnd: 72, valueStart: 73, valueEnd: 73},
				{name: "key2", value: "value", nameStart: 74, nameEnd: 78, valueStart: 79, valueEnd: 84},
				{name: "key3", value: "", nameStart: 85, nameEnd: 89, valueStart: 90, valueEnd: 90},
			},
		},
		{
			name: "POST with flag parameters (no equals)",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"flag1&key=value&flag2"),
			expected: 3,
			checks: []paramCheck{
				{name: "flag1", value: "", nameStart: 68, nameEnd: 73, valueStart: 73, valueEnd: 73},
				{name: "key", value: "value", nameStart: 74, nameEnd: 77, valueStart: 78, valueEnd: 83},
				{name: "flag2", value: "", nameStart: 84, nameEnd: 89, valueStart: 89, valueEnd: 89},
			},
		},
		{
			name: "POST with special characters",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"email=test%40example.com&msg=hello%2Bworld"),
			expected: 2,
			checks: []paramCheck{
				{name: "email", value: "test@example.com", nameStart: 68, nameEnd: 73, valueStart: 74, valueEnd: 92},
				{name: "msg", value: "hello+world", nameStart: 93, nameEnd: 96, valueStart: 97, valueEnd: 110},
			},
		},
		{
			name: "POST with trailing ampersand",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"a=1&b=2&"),
			expected: 2,
			checks: []paramCheck{
				{name: "a", value: "1", nameStart: 68, nameEnd: 69, valueStart: 70, valueEnd: 71},
				{name: "b", value: "2", nameStart: 72, nameEnd: 73, valueStart: 74, valueEnd: 75},
			},
		},
		{
			name: "POST with empty body",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n"),
			expected: 0,
			checks:   []paramCheck{},
		},
		{
			name: "POST with leading newlines in body",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"\r\nfoo=bar"),
			expected: 1,
			checks: []paramCheck{
				{name: "foo", value: "bar", nameStart: 70, nameEnd: 73, valueStart: 74, valueEnd: 77},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Find body offset
			bodyOffset := FindBodyOffset(tt.request)

			// Parse parameters
			params, err := ParseURLEncodedBody(tt.request, bodyOffset)
			if err != nil {
				t.Errorf("ParseURLEncodedBody() error = %v", err)
				return
			}

			if len(params) != tt.expected {
				t.Errorf("ParseURLEncodedBody() got %d parameters, want %d", len(params), tt.expected)
				return
			}

			// Verify each parameter
			for i, check := range tt.checks {
				if i >= len(params) {
					t.Errorf("Missing parameter %d", i)
					continue
				}

				param := params[i]

				// Check type is ParamBody
				if param.Type() != ParamBody {
					t.Errorf("Parameter[%d].Type = %v, want ParamBody", i, param.Type())
				}

				if param.Name() != check.name {
					t.Errorf("Parameter[%d].Name = %q, want %q", i, param.Name(), check.name)
				}

				if param.Value() != check.value {
					t.Errorf("Parameter[%d].Value = %q, want %q", i, param.Value(), check.value)
				}

				if param.NameStart() != check.nameStart {
					t.Errorf("Parameter[%d].NameStart = %d, want %d", i, param.NameStart(), check.nameStart)
				}

				if param.NameEnd() != check.nameEnd {
					t.Errorf("Parameter[%d].NameEnd = %d, want %d", i, param.NameEnd(), check.nameEnd)
				}

				if param.ValueStart() != check.valueStart {
					t.Errorf("Parameter[%d].ValueStart = %d, want %d", i, param.ValueStart(), check.valueStart)
				}

				if param.ValueEnd() != check.valueEnd {
					t.Errorf("Parameter[%d].ValueEnd = %d, want %d", i, param.ValueEnd(), check.valueEnd)
				}
			}
		})
	}
}

// TestGetBodyBytes tests body extraction
func TestGetBodyBytes(t *testing.T) {
	tests := []struct {
		name       string
		request    []byte
		bodyOffset int
		expected   string
	}{
		{
			name: "normal body extraction",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"name=value"),
			bodyOffset: 68,
			expected:   "name=value",
		},
		{
			name: "empty body",
			request: []byte("POST / HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n"),
			bodyOffset: 68,
			expected:   "",
		},
		{
			name:       "invalid offset (negative)",
			request:    []byte("POST / HTTP/1.1\r\n\r\nbody"),
			bodyOffset: -1,
			expected:   "",
		},
		{
			name:       "invalid offset (beyond length)",
			request:    []byte("POST / HTTP/1.1\r\n\r\nbody"),
			bodyOffset: 1000,
			expected:   "",
		},
		{
			name:       "nil request",
			request:    nil,
			bodyOffset: 0,
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetBodyBytes(tt.request, tt.bodyOffset)
			resultStr := string(result)

			if resultStr != tt.expected {
				t.Errorf("GetBodyBytes() = %q, want %q", resultStr, tt.expected)
			}
		})
	}
}

// TestHasURLEncodedBody tests Content-Type detection
func TestHasURLEncodedBody(t *testing.T) {
	tests := []struct {
		name     string
		headers  []string
		expected bool
	}{
		{
			name: "URL-encoded content type",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: application/x-www-form-urlencoded",
				"Content-Length: 10",
			},
			expected: true,
		},
		{
			name: "URL-encoded with charset",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
			},
			expected: true,
		},
		{
			name: "URL-encoded uppercase",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: APPLICATION/X-WWW-FORM-URLENCODED",
			},
			expected: true,
		},
		{
			name: "multipart content type",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: multipart/form-data; boundary=----WebKit",
			},
			expected: false,
		},
		{
			name: "JSON content type",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: application/json",
			},
			expected: false,
		},
		{
			name: "XML content type",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: application/xml",
			},
			expected: false,
		},
		{
			name: "no content type header",
			headers: []string{
				"POST / HTTP/1.1",
				"Host: example.com",
			},
			expected: false,
		},
		{
			name:     "empty headers",
			headers:  []string{},
			expected: false,
		},
		{
			name:     "nil headers",
			headers:  nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasURLEncodedBody(tt.headers)
			if result != tt.expected {
				t.Errorf("HasURLEncodedBody() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestParseURLEncodedBodyString tests parsing from string
func TestParseURLEncodedBodyString(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected int
		checks   []paramCheck
	}{
		{
			name:     "simple parameters",
			body:     "foo=bar&name=value",
			expected: 2,
			checks: []paramCheck{
				{name: "foo", value: "bar", nameStart: 0, nameEnd: 3, valueStart: 4, valueEnd: 7},
				{name: "name", value: "value", nameStart: 8, nameEnd: 12, valueStart: 13, valueEnd: 18},
			},
		},
		{
			name:     "URL-encoded values",
			body:     "name=John%20Doe&city=New%20York",
			expected: 2,
			checks: []paramCheck{
				{name: "name", value: "John Doe", nameStart: 0, nameEnd: 4, valueStart: 5, valueEnd: 15},
				{name: "city", value: "New York", nameStart: 16, nameEnd: 20, valueStart: 21, valueEnd: 31},
			},
		},
		{
			name:     "empty string",
			body:     "",
			expected: 0,
			checks:   []paramCheck{},
		},
		{
			name:     "single parameter",
			body:     "key=value",
			expected: 1,
			checks: []paramCheck{
				{name: "key", value: "value", nameStart: 0, nameEnd: 3, valueStart: 4, valueEnd: 9},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseURLEncodedBodyString(tt.body)
			if err != nil {
				t.Errorf("ParseURLEncodedBodyString() error = %v", err)
				return
			}

			if len(params) != tt.expected {
				t.Errorf("ParseURLEncodedBodyString() got %d parameters, want %d", len(params), tt.expected)
				return
			}

			for i, check := range tt.checks {
				if i >= len(params) {
					t.Errorf("Missing parameter %d", i)
					continue
				}

				param := params[i]

				if param.Type() != ParamBody {
					t.Errorf("Parameter[%d].Type = %v, want ParamBody", i, param.Type())
				}

				if param.Name() != check.name {
					t.Errorf("Parameter[%d].Name = %q, want %q", i, param.Name(), check.name)
				}

				if param.Value() != check.value {
					t.Errorf("Parameter[%d].Value = %q, want %q", i, param.Value(), check.value)
				}

				if param.NameStart() != check.nameStart {
					t.Errorf("Parameter[%d].NameStart = %d, want %d", i, param.NameStart(), check.nameStart)
				}

				if param.NameEnd() != check.nameEnd {
					t.Errorf("Parameter[%d].NameEnd = %d, want %d", i, param.NameEnd(), check.nameEnd)
				}

				if param.ValueStart() != check.valueStart {
					t.Errorf("Parameter[%d].ValueStart = %d, want %d", i, param.ValueStart(), check.valueStart)
				}

				if param.ValueEnd() != check.valueEnd {
					t.Errorf("Parameter[%d].ValueEnd = %d, want %d", i, param.ValueEnd(), check.valueEnd)
				}
			}
		})
	}
}

// TestExtractBodyParameters tests full request parameter extraction
func TestExtractBodyParameters(t *testing.T) {
	tests := []struct {
		name           string
		request        []byte
		expectedParams int
		expectedOffset int
		checks         []paramCheck
	}{
		{
			name: "URL-encoded POST request",
			request: []byte("POST /api HTTP/1.1\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"\r\n" +
				"key=value&foo=bar"),
			expectedParams: 2,
			expectedOffset: 71,
			checks: []paramCheck{
				{name: "key", value: "value", nameStart: 71, nameEnd: 74, valueStart: 75, valueEnd: 80},
				{name: "foo", value: "bar", nameStart: 81, nameEnd: 84, valueStart: 85, valueEnd: 88},
			},
		},
		{
			name: "JSON POST request (should return empty)",
			request: []byte("POST /api HTTP/1.1\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				"{\"key\":\"value\"}"),
			expectedParams: 0,
			expectedOffset: 54,
			checks:         []paramCheck{},
		},
		{
			name: "GET request (no body)",
			request: []byte("GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n"),
			expectedParams: 0,
			expectedOffset: 37,
			checks:         []paramCheck{},
		},
		{
			name:           "nil request",
			request:        nil,
			expectedParams: 0,
			expectedOffset: 0,
			checks:         []paramCheck{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, offset, err := ExtractBodyParameters(tt.request)
			if err != nil {
				t.Errorf("ExtractBodyParameters() error = %v", err)
				return
			}

			if len(params) != tt.expectedParams {
				t.Errorf("ExtractBodyParameters() got %d parameters, want %d", len(params), tt.expectedParams)
			}

			if offset != tt.expectedOffset {
				t.Errorf("ExtractBodyParameters() offset = %d, want %d", offset, tt.expectedOffset)
			}

			for i, check := range tt.checks {
				if i >= len(params) {
					t.Errorf("Missing parameter %d", i)
					continue
				}

				param := params[i]

				if param.Type() != ParamBody {
					t.Errorf("Parameter[%d].Type = %v, want ParamBody", i, param.Type())
				}

				if param.Name() != check.name {
					t.Errorf("Parameter[%d].Name = %q, want %q", i, param.Name(), check.name)
				}

				if param.Value() != check.value {
					t.Errorf("Parameter[%d].Value = %q, want %q", i, param.Value(), check.value)
				}

				if param.NameStart() != check.nameStart {
					t.Errorf("Parameter[%d].NameStart = %d, want %d", i, param.NameStart(), check.nameStart)
				}

				if param.NameEnd() != check.nameEnd {
					t.Errorf("Parameter[%d].NameEnd = %d, want %d", i, param.NameEnd(), check.nameEnd)
				}

				if param.ValueStart() != check.valueStart {
					t.Errorf("Parameter[%d].ValueStart = %d, want %d", i, param.ValueStart(), check.valueStart)
				}

				if param.ValueEnd() != check.valueEnd {
					t.Errorf("Parameter[%d].ValueEnd = %d, want %d", i, param.ValueEnd(), check.valueEnd)
				}
			}
		})
	}
}

// TestGetBodyContentType tests content type detection
func TestGetBodyContentType(t *testing.T) {
	tests := []struct {
		name       string
		headers    []string
		request    []byte
		bodyOffset int
		expected   ContentType
	}{
		{
			name: "URL-encoded",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: application/x-www-form-urlencoded",
			},
			request:    []byte("POST / HTTP/1.1\r\n\r\nbody"),
			bodyOffset: 19,
			expected:   ContentTypeURLEncoded,
		},
		{
			name: "JSON",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: application/json",
			},
			request:    []byte("POST / HTTP/1.1\r\n\r\nbody"),
			bodyOffset: 19,
			expected:   ContentTypeJSON,
		},
		{
			name: "XML",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: text/xml",
			},
			request:    []byte("POST / HTTP/1.1\r\n\r\nbody"),
			bodyOffset: 19,
			expected:   ContentTypeXML,
		},
		{
			name: "Multipart",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: multipart/form-data",
			},
			request:    []byte("POST / HTTP/1.1\r\n\r\nbody"),
			bodyOffset: 19,
			expected:   ContentTypeMultipart,
		},
		{
			name: "no body",
			headers: []string{
				"GET / HTTP/1.1",
			},
			request:    []byte("GET / HTTP/1.1\r\n\r\n"),
			bodyOffset: -1,
			expected:   ContentTypeNone,
		},
		{
			name: "no Content-Type header",
			headers: []string{
				"POST / HTTP/1.1",
			},
			request:    []byte("POST / HTTP/1.1\r\n\r\nbody"),
			bodyOffset: 19,
			expected:   ContentTypeURLEncoded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetBodyContentType(tt.headers, tt.request, tt.bodyOffset)
			if result != tt.expected {
				t.Errorf("GetBodyContentType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestContainsSubstring tests case-insensitive substring search
func TestContainsSubstring(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected bool
	}{
		{
			name:     "exact match",
			s:        "hello",
			substr:   "hello",
			expected: true,
		},
		{
			name:     "substring at start",
			s:        "hello world",
			substr:   "hello",
			expected: true,
		},
		{
			name:     "substring at end",
			s:        "hello world",
			substr:   "world",
			expected: true,
		},
		{
			name:     "substring in middle",
			s:        "hello world",
			substr:   "lo wo",
			expected: true,
		},
		{
			name:     "case insensitive match",
			s:        "Hello World",
			substr:   "HELLO",
			expected: true,
		},
		{
			name:     "not found",
			s:        "hello world",
			substr:   "foo",
			expected: false,
		},
		{
			name:     "empty substring",
			s:        "hello",
			substr:   "",
			expected: true,
		},
		{
			name:     "substring longer than string",
			s:        "hi",
			substr:   "hello",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSubstring(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("containsSubstring(%q, %q) = %v, want %v", tt.s, tt.substr, result, tt.expected)
			}
		})
	}
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	t.Run("body with only ampersands", func(t *testing.T) {
		request := []byte("POST / HTTP/1.1\r\n\r\n&&&")
		bodyOffset := FindBodyOffset(request)
		params, _ := ParseURLEncodedBody(request, bodyOffset)

		if len(params) != 0 {
			t.Errorf("Expected 0 parameters for body '&&&', got %d", len(params))
		}
	})

	t.Run("body with only equals signs", func(t *testing.T) {
		request := []byte("POST / HTTP/1.1\r\n\r\n===")
		bodyOffset := FindBodyOffset(request)
		params, _ := ParseURLEncodedBody(request, bodyOffset)

		// Should create parameters with empty names
		if len(params) != 0 {
			t.Errorf("Expected 0 parameters for body '===', got %d", len(params))
		}
	})

	t.Run("very long parameter name", func(t *testing.T) {
		longName := ""
		for i := 0; i < 1000; i++ {
			longName += "a"
		}
		body := longName + "=value"
		params, _ := ParseURLEncodedBodyString(body)

		if len(params) != 1 {
			t.Errorf("Expected 1 parameter, got %d", len(params))
			return
		}

		if params[0].Name() != longName {
			t.Errorf("Parameter name mismatch")
		}
	})

	t.Run("very long parameter value", func(t *testing.T) {
		longValue := ""
		for i := 0; i < 1000; i++ {
			longValue += "v"
		}
		body := "key=" + longValue
		params, _ := ParseURLEncodedBodyString(body)

		if len(params) != 1 {
			t.Errorf("Expected 1 parameter, got %d", len(params))
			return
		}

		if params[0].Value() != longValue {
			t.Errorf("Parameter value mismatch")
		}
	})
}

// Benchmark tests

func BenchmarkParseURLEncodedBody(b *testing.B) {
	request := []byte("POST / HTTP/1.1\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"\r\n" +
		"username=admin&password=secret123&email=test%40example.com&age=30&city=New%20York")
	bodyOffset := FindBodyOffset(request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseURLEncodedBody(request, bodyOffset)
	}
}

func BenchmarkParseURLEncodedBodyString(b *testing.B) {
	body := "username=admin&password=secret123&email=test%40example.com&age=30&city=New%20York&country=USA&zip=12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseURLEncodedBodyString(body)
	}
}

func BenchmarkExtractBodyParameters(b *testing.B) {
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 100\r\n" +
		"\r\n" +
		"username=admin&password=secret&email=test%40example.com&remember=on")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ExtractBodyParameters(request)
	}
}
