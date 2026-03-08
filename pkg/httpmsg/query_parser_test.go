package httpmsg

import (
	"testing"
)

// TestParseQueryString tests basic query string parsing
func TestParseQueryString(t *testing.T) {
	tests := []struct {
		name     string
		url      []byte
		expected int // number of parameters
		checks   []paramCheck
	}{
		{
			name:     "single parameter",
			url:      []byte("http://example.com?foo=bar"),
			expected: 1,
			checks: []paramCheck{
				{name: "foo", value: "bar", nameStart: 19, nameEnd: 22, valueStart: 23, valueEnd: 26},
			},
		},
		{
			name:     "multiple parameters",
			url:      []byte("http://example.com?a=1&b=2&c=3"),
			expected: 3,
			checks: []paramCheck{
				{name: "a", value: "1", nameStart: 19, nameEnd: 20, valueStart: 21, valueEnd: 22},
				{name: "b", value: "2", nameStart: 23, nameEnd: 24, valueStart: 25, valueEnd: 26},
				{name: "c", value: "3", nameStart: 27, nameEnd: 28, valueStart: 29, valueEnd: 30},
			},
		},
		{
			name:     "url encoded values",
			url:      []byte("http://example.com?name=John%20Doe&city=New%20York"),
			expected: 2,
			checks: []paramCheck{
				{name: "name", value: "John Doe", nameStart: 19, nameEnd: 23, valueStart: 24, valueEnd: 34},
				{name: "city", value: "New York", nameStart: 35, nameEnd: 39, valueStart: 40, valueEnd: 50},
			},
		},
		{
			name:     "plus encoding",
			url:      []byte("http://example.com?search=hello+world"),
			expected: 1,
			checks: []paramCheck{
				{name: "search", value: "hello world", nameStart: 19, nameEnd: 25, valueStart: 26, valueEnd: 37},
			},
		},
		{
			name:     "empty value",
			url:      []byte("http://example.com?key="),
			expected: 1,
			checks: []paramCheck{
				{name: "key", value: "", nameStart: 19, nameEnd: 22, valueStart: 23, valueEnd: 23},
			},
		},
		{
			name:     "no value (flag parameter)",
			url:      []byte("http://example.com?flag"),
			expected: 1,
			checks: []paramCheck{
				{name: "flag", value: "", nameStart: 19, nameEnd: 23, valueStart: 23, valueEnd: 23},
			},
		},
		{
			name:     "parameter with fragment",
			url:      []byte("http://example.com?param=value#anchor"),
			expected: 1,
			checks: []paramCheck{
				{name: "param", value: "value", nameStart: 19, nameEnd: 24, valueStart: 25, valueEnd: 30},
			},
		},
		{
			name:     "mixed empty and valued parameters",
			url:      []byte("http://example.com?a=1&b=&c&d=4"),
			expected: 4,
			checks: []paramCheck{
				{name: "a", value: "1", nameStart: 19, nameEnd: 20, valueStart: 21, valueEnd: 22},
				{name: "b", value: "", nameStart: 23, nameEnd: 24, valueStart: 25, valueEnd: 25},
				{name: "c", value: "", nameStart: 26, nameEnd: 27, valueStart: 27, valueEnd: 27},
				{name: "d", value: "4", nameStart: 28, nameEnd: 29, valueStart: 30, valueEnd: 31},
			},
		},
		{
			name:     "trailing ampersand",
			url:      []byte("http://example.com?a=1&b=2&"),
			expected: 2,
			checks: []paramCheck{
				{name: "a", value: "1", nameStart: 19, nameEnd: 20, valueStart: 21, valueEnd: 22},
				{name: "b", value: "2", nameStart: 23, nameEnd: 24, valueStart: 25, valueEnd: 26},
			},
		},
		{
			name:     "no query string",
			url:      []byte("http://example.com/path"),
			expected: 0,
			checks:   []paramCheck{},
		},
		{
			name:     "empty query string",
			url:      []byte("http://example.com?"),
			expected: 0,
			checks:   []paramCheck{},
		},
		{
			name:     "special characters in values",
			url:      []byte("http://example.com?a=hello%2Bworld&b=foo%3Dbar"),
			expected: 2,
			checks: []paramCheck{
				{name: "a", value: "hello+world", nameStart: 19, nameEnd: 20, valueStart: 21, valueEnd: 34},
				{name: "b", value: "foo=bar", nameStart: 35, nameEnd: 36, valueStart: 37, valueEnd: 46},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParseQueryString(tt.url)
			if err != nil {
				t.Errorf("ParseQueryString() error = %v", err)
				return
			}

			if len(params) != tt.expected {
				t.Errorf("ParseQueryString() got %d parameters, want %d", len(params), tt.expected)
				return
			}

			for i, check := range tt.checks {
				if i >= len(params) {
					t.Errorf("Missing parameter %d", i)
					continue
				}
				checkParameter(t, params[i], check, i)
			}
		})
	}
}

// TestExtractQueryParameters tests extracting query params from HTTP requests
func TestExtractQueryParameters(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		urlStart int
		urlEnd   int
		expected int
		checks   []paramCheck
	}{
		{
			name:     "GET request with query params",
			request:  []byte("GET /path?foo=bar&name=value HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			urlStart: 4,
			urlEnd:   28,
			expected: 2,
			checks: []paramCheck{
				{name: "foo", value: "bar", nameStart: 10, nameEnd: 13, valueStart: 14, valueEnd: 17},
				{name: "name", value: "value", nameStart: 18, nameEnd: 22, valueStart: 23, valueEnd: 28},
			},
		},
		{
			name:     "POST request with query params",
			request:  []byte("POST /api?key=value HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			urlStart: 5,
			urlEnd:   19,
			expected: 1,
			checks: []paramCheck{
				{name: "key", value: "value", nameStart: 10, nameEnd: 13, valueStart: 14, valueEnd: 19},
			},
		},
		{
			name:     "request with no query params",
			request:  []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			urlStart: 4,
			urlEnd:   9,
			expected: 0,
			checks:   []paramCheck{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ExtractQueryParameters(tt.request, tt.urlStart, tt.urlEnd)
			if err != nil {
				t.Errorf("ExtractQueryParameters() error = %v", err)
				return
			}

			if len(params) != tt.expected {
				t.Errorf("ExtractQueryParameters() got %d parameters, want %d", len(params), tt.expected)
				return
			}

			for i, check := range tt.checks {
				if i >= len(params) {
					t.Errorf("Missing parameter %d", i)
					continue
				}
				checkParameter(t, params[i], check, i)
			}
		})
	}
}

// TestFindQueryBounds tests query string boundary detection
func TestFindQueryBounds(t *testing.T) {
	tests := []struct {
		name     string
		url      []byte
		expected []int // nil if no query string
	}{
		{
			name:     "query string with fragment",
			url:      []byte("http://example.com/path?foo=bar#anchor"),
			expected: []int{23, 31},
		},
		{
			name:     "query string without fragment",
			url:      []byte("http://example.com/path?foo=bar"),
			expected: []int{23, 31},
		},
		{
			name:     "empty query string",
			url:      []byte("http://example.com/path?"),
			expected: []int{23, 24},
		},
		{
			name:     "no query string",
			url:      []byte("http://example.com/path"),
			expected: nil,
		},
		{
			name:     "fragment before query string",
			url:      []byte("http://example.com/path#anchor?invalid"),
			expected: nil,
		},
		{
			name:     "query string with space",
			url:      []byte("http://example.com?foo=bar baz"),
			expected: []int{18, 26}, // Stops at space (32)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findQueryBounds(tt.url)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("findQueryBounds() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Errorf("findQueryBounds() = nil, want %v", tt.expected)
				return
			}

			if len(result) != 2 {
				t.Errorf("findQueryBounds() returned %d elements, want 2", len(result))
				return
			}

			if result[0] != tt.expected[0] || result[1] != tt.expected[1] {
				t.Errorf("findQueryBounds() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestFindQueryStart tests finding the '?' character
func TestFindQueryStart(t *testing.T) {
	tests := []struct {
		name     string
		url      []byte
		expected int
	}{
		{
			name:     "url with query string",
			url:      []byte("http://example.com?foo=bar"),
			expected: 18,
		},
		{
			name:     "url without query string",
			url:      []byte("http://example.com/path"),
			expected: -1,
		},
		{
			name:     "empty url",
			url:      []byte(""),
			expected: -1,
		},
		{
			name:     "nil url",
			url:      nil,
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindQueryStart(tt.url)
			if result != tt.expected {
				t.Errorf("FindQueryStart() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestFindQueryEndFromURLParser tests the FindQueryEnd function from url_parser.go
// Note: FindQueryEnd is defined in url_parser.go, this test validates it works for query parsing
func TestFindQueryEndFromURLParser(t *testing.T) {
	tests := []struct {
		name       string
		url        []byte
		queryStart int
		expected   int
	}{
		{
			name:       "query string with fragment",
			url:        []byte("http://example.com?foo=bar#anchor"),
			queryStart: 19, // After '?'
			expected:   26,
		},
		{
			name:       "query string without fragment",
			url:        []byte("http://example.com?foo=bar"),
			queryStart: 19, // After '?'
			expected:   26,
		},
		{
			name:       "empty query string",
			url:        []byte("http://example.com?"),
			queryStart: 19, // After '?'
			expected:   19,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindQueryEnd(tt.url, tt.queryStart)
			if result != tt.expected {
				t.Errorf("FindQueryEnd() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestDecodeQueryValue tests URL decoding
func TestDecodeQueryValue(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		expected string
	}{
		{
			name:     "percent encoding",
			encoded:  "John%20Doe",
			expected: "John Doe",
		},
		{
			name:     "plus encoding",
			encoded:  "hello+world",
			expected: "hello world",
		},
		{
			name:     "mixed encoding",
			encoded:  "John+Doe%20Smith",
			expected: "John Doe Smith",
		},
		{
			name:     "special characters",
			encoded:  "hello%2Bworld",
			expected: "hello+world",
		},
		{
			name:     "equals and ampersand",
			encoded:  "a%3Db%26c%3Dd",
			expected: "a=b&c=d",
		},
		{
			name:     "no encoding",
			encoded:  "plaintext",
			expected: "plaintext",
		},
		{
			name:     "empty string",
			encoded:  "",
			expected: "",
		},
		{
			name:     "invalid percent encoding",
			encoded:  "test%ZZ",
			expected: "test%ZZ", // Invalid encoding kept as-is
		},
		{
			name:     "incomplete percent encoding",
			encoded:  "test%2",
			expected: "test%2", // Incomplete encoding kept as-is
		},
		{
			name:     "lowercase hex",
			encoded:  "test%2bvalue",
			expected: "test+value",
		},
		{
			name:     "uppercase hex",
			encoded:  "test%2Bvalue",
			expected: "test+value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecodeQueryValue(tt.encoded)
			if result != tt.expected {
				t.Errorf("DecodeQueryValue(%q) = %q, want %q", tt.encoded, result, tt.expected)
			}
		})
	}
}

// TestHexCharToValue tests hex character conversion
func TestHexCharToValue(t *testing.T) {
	tests := []struct {
		name     string
		ch       byte
		expected int
	}{
		{name: "digit 0", ch: '0', expected: 0},
		{name: "digit 5", ch: '5', expected: 5},
		{name: "digit 9", ch: '9', expected: 9},
		{name: "lowercase a", ch: 'a', expected: 10},
		{name: "lowercase f", ch: 'f', expected: 15},
		{name: "uppercase A", ch: 'A', expected: 10},
		{name: "uppercase F", ch: 'F', expected: 15},
		{name: "invalid G", ch: 'G', expected: -1},
		{name: "invalid space", ch: ' ', expected: -1},
		{name: "invalid symbol", ch: '!', expected: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HexCharToValue(tt.ch)
			if result != tt.expected {
				t.Errorf("HexCharToValue('%c') = %d, want %d", tt.ch, result, tt.expected)
			}
		})
	}
}

// TestEncodeQueryValue tests URL encoding
func TestEncodeQueryValue(t *testing.T) {
	tests := []struct {
		name     string
		decoded  string
		expected string
	}{
		{
			name:     "space to plus",
			decoded:  "John Doe",
			expected: "John+Doe",
		},
		{
			name:     "plus sign",
			decoded:  "hello+world",
			expected: "hello%2Bworld",
		},
		{
			name:     "equals and ampersand",
			decoded:  "a=b&c=d",
			expected: "a%3Db%26c%3Dd",
		},
		{
			name:     "alphanumeric unchanged",
			decoded:  "abc123XYZ",
			expected: "abc123XYZ",
		},
		{
			name:     "unreserved characters",
			decoded:  "test-value_2024.file~backup",
			expected: "test-value_2024.file~backup",
		},
		{
			name:     "special characters",
			decoded:  "!@#$%^&*()",
			expected: "%21%40%23%24%25%5E%26%2A%28%29",
		},
		{
			name:     "empty string",
			decoded:  "",
			expected: "",
		},
		{
			name:     "unicode characters",
			decoded:  "hello世界",
			expected: "hello%E4%B8%96%E7%95%8C",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeQueryValue(tt.decoded)
			if result != tt.expected {
				t.Errorf("EncodeQueryValue(%q) = %q, want %q", tt.decoded, result, tt.expected)
			}
		})
	}
}

// TestParseURLEncodedParameters tests the core parameter parsing function
func TestParseURLEncodedParameters(t *testing.T) {
	tests := []struct {
		name      string
		paramType ParamType
		data      []byte
		start     int
		end       int
		expected  int
		checks    []paramCheck
	}{
		{
			name:      "basic parsing",
			paramType: ParamURL,
			data:      []byte("foo=bar&name=value"),
			start:     0,
			end:       18,
			expected:  2,
			checks: []paramCheck{
				{name: "foo", value: "bar", nameStart: 0, nameEnd: 3, valueStart: 4, valueEnd: 7},
				{name: "name", value: "value", nameStart: 8, nameEnd: 12, valueStart: 13, valueEnd: 18},
			},
		},
		{
			name:      "with leading newlines",
			paramType: ParamBody,
			data:      []byte("\r\nfoo=bar"),
			start:     0,
			end:       9,
			expected:  1,
			checks: []paramCheck{
				{name: "foo", value: "bar", nameStart: 2, nameEnd: 5, valueStart: 6, valueEnd: 9},
			},
		},
		{
			name:      "empty range",
			paramType: ParamURL,
			data:      []byte("foo=bar"),
			start:     5,
			end:       5,
			expected:  0,
			checks:    []paramCheck{},
		},
		{
			name:      "nil data",
			paramType: ParamURL,
			data:      nil,
			start:     0,
			end:       0,
			expected:  0,
			checks:    []paramCheck{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := parseURLEncodedParameters(tt.paramType, tt.data, tt.start, tt.end)

			if len(params) != tt.expected {
				t.Errorf("parseURLEncodedParameters() got %d parameters, want %d", len(params), tt.expected)
				return
			}

			for i, check := range tt.checks {
				if i >= len(params) {
					t.Errorf("Missing parameter %d", i)
					continue
				}
				checkParameter(t, params[i], check, i)
			}
		})
	}
}

// Helper types and functions

type paramCheck struct {
	name       string
	value      string
	nameStart  int
	nameEnd    int
	valueStart int
	valueEnd   int
}

func checkParameter(t *testing.T, param *Param, check paramCheck, index int) {
	t.Helper()

	if param.Type() != ParamURL && param.Type() != ParamBody {
		t.Errorf("Parameter[%d].Type = %v, want ParamURL or ParamBody", index, param.Type())
	}

	if param.Name() != check.name {
		t.Errorf("Parameter[%d].Name = %q, want %q", index, param.Name(), check.name)
	}

	if param.Value() != check.value {
		t.Errorf("Parameter[%d].Value = %q, want %q", index, param.Value(), check.value)
	}

	if param.NameStart() != check.nameStart {
		t.Errorf("Parameter[%d].NameStart = %d, want %d", index, param.NameStart(), check.nameStart)
	}

	if param.NameEnd() != check.nameEnd {
		t.Errorf("Parameter[%d].NameEnd = %d, want %d", index, param.NameEnd(), check.nameEnd)
	}

	if param.ValueStart() != check.valueStart {
		t.Errorf("Parameter[%d].ValueStart = %d, want %d", index, param.ValueStart(), check.valueStart)
	}

	if param.ValueEnd() != check.valueEnd {
		t.Errorf("Parameter[%d].ValueEnd = %d, want %d", index, param.ValueEnd(), check.valueEnd)
	}
}

// Benchmark tests

func BenchmarkParseQueryString(b *testing.B) {
	url := []byte("http://example.com/path?foo=bar&name=John%20Doe&age=30&city=New%20York&country=USA")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseQueryString(url)
	}
}

func BenchmarkDecodeQueryValue(b *testing.B) {
	encoded := "John%20Doe%2BSmith%26Associates"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeQueryValue(encoded)
	}
}

func BenchmarkEncodeQueryValue(b *testing.B) {
	decoded := "John Doe+Smith&Associates"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeQueryValue(decoded)
	}
}
