package httpmsg

import "testing"

// TestIndexOf tests the IndexOf function for pattern matching.
func TestIndexOf(t *testing.T) {
	tests := []struct {
		name          string
		haystack      []byte
		needle        []byte
		caseSensitive bool
		start         int
		end           int
		want          int
	}{
		{
			name:          "simple match case-sensitive",
			haystack:      []byte("Hello World"),
			needle:        []byte("World"),
			caseSensitive: true,
			start:         0,
			end:           11,
			want:          6,
		},
		{
			name:          "simple match case-insensitive",
			haystack:      []byte("Hello World"),
			needle:        []byte("world"),
			caseSensitive: false,
			start:         0,
			end:           11,
			want:          6,
		},
		{
			name:          "no match case-sensitive",
			haystack:      []byte("Hello World"),
			needle:        []byte("world"),
			caseSensitive: true,
			start:         0,
			end:           11,
			want:          -1,
		},
		{
			name:          "match at beginning",
			haystack:      []byte("Hello World"),
			needle:        []byte("Hello"),
			caseSensitive: true,
			start:         0,
			end:           11,
			want:          0,
		},
		{
			name:          "match at end",
			haystack:      []byte("Hello World"),
			needle:        []byte("World"),
			caseSensitive: true,
			start:         0,
			end:           11,
			want:          6,
		},
		{
			name:          "empty needle",
			haystack:      []byte("Hello World"),
			needle:        []byte(""),
			caseSensitive: true,
			start:         0,
			end:           11,
			want:          0,
		},
		{
			name:          "needle longer than haystack",
			haystack:      []byte("Hi"),
			needle:        []byte("Hello"),
			caseSensitive: true,
			start:         0,
			end:           2,
			want:          -1,
		},
		{
			name:          "search with start offset",
			haystack:      []byte("Hello Hello"),
			needle:        []byte("Hello"),
			caseSensitive: true,
			start:         1,
			end:           11,
			want:          6,
		},
		{
			name:          "search with limited end",
			haystack:      []byte("Hello World"),
			needle:        []byte("World"),
			caseSensitive: true,
			start:         0,
			end:           5,
			want:          -1,
		},
		{
			name:          "null haystack",
			haystack:      nil,
			needle:        []byte("test"),
			caseSensitive: true,
			start:         0,
			end:           0,
			want:          -1,
		},
		{
			name:          "null needle",
			haystack:      []byte("test"),
			needle:        nil,
			caseSensitive: true,
			start:         0,
			end:           4,
			want:          -1,
		},
		{
			name:          "negative start",
			haystack:      []byte("Hello"),
			needle:        []byte("Hello"),
			caseSensitive: true,
			start:         -1,
			end:           5,
			want:          -1,
		},
		{
			name:          "end before start",
			haystack:      []byte("Hello"),
			needle:        []byte("Hello"),
			caseSensitive: true,
			start:         5,
			end:           0,
			want:          -1,
		},
		{
			name:          "end beyond length",
			haystack:      []byte("Hello"),
			needle:        []byte("Hello"),
			caseSensitive: true,
			start:         0,
			end:           100,
			want:          -1,
		},
		{
			name:          "HTTP header search",
			haystack:      []byte("Content-Type: application/json"),
			needle:        []byte("application/json"),
			caseSensitive: true,
			start:         0,
			end:           30,
			want:          14,
		},
		{
			name:          "case-insensitive header",
			haystack:      []byte("Content-Type: Application/JSON"),
			needle:        []byte("application/json"),
			caseSensitive: false,
			start:         0,
			end:           30,
			want:          14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IndexOf(tt.haystack, tt.needle, tt.caseSensitive, tt.start, tt.end)
			if got != tt.want {
				t.Errorf("IndexOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetRequestParameter tests finding parameters in HTTP requests.
func TestGetRequestParameter(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		paramName string
		wantName  string
		wantValue string
		wantType  ParamType
		wantNil   bool
		wantErr   bool
	}{
		{
			name:      "URL parameter",
			request:   []byte("GET /api?id=123&name=test HTTP/1.1\r\n\r\n"),
			paramName: "id",
			wantName:  "id",
			wantValue: "123",
			wantType:  ParamURL,
			wantNil:   false,
			wantErr:   false,
		},
		{
			name:      "URL parameter - second param",
			request:   []byte("GET /api?id=123&name=test HTTP/1.1\r\n\r\n"),
			paramName: "name",
			wantName:  "name",
			wantValue: "test",
			wantType:  ParamURL,
			wantNil:   false,
			wantErr:   false,
		},
		{
			name:      "cookie parameter",
			request:   []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"),
			paramName: "session",
			wantName:  "session",
			wantValue: "abc123",
			wantType:  ParamCookie,
			wantNil:   false,
			wantErr:   false,
		},
		{
			name:      "body parameter",
			request:   []byte("POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=john&pass=secret"),
			paramName: "user",
			wantName:  "user",
			wantValue: "john",
			wantType:  ParamBody,
			wantNil:   false,
			wantErr:   false,
		},
		{
			name:      "JSON parameter",
			request:   []byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"action\":\"update\"}"),
			paramName: "action",
			wantName:  "action",
			wantValue: "update",
			wantType:  ParamJSON,
			wantNil:   false,
			wantErr:   false,
		},
		{
			name:      "parameter not found",
			request:   []byte("GET /api?id=123 HTTP/1.1\r\n\r\n"),
			paramName: "missing",
			wantNil:   true,
			wantErr:   false,
		},
		{
			name:      "null request",
			request:   nil,
			paramName: "test",
			wantNil:   true,
			wantErr:   true,
		},
		{
			name:      "empty parameter name",
			request:   []byte("GET / HTTP/1.1\r\n\r\n"),
			paramName: "",
			wantNil:   true,
			wantErr:   true,
		},
		{
			name:      "multiple cookies",
			request:   []byte("GET / HTTP/1.1\r\nCookie: session=abc; user=john\r\n\r\n"),
			paramName: "user",
			wantName:  "user",
			wantValue: "john",
			wantType:  ParamCookie,
			wantNil:   false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			param, err := GetRequestParameter(tt.request, tt.paramName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetRequestParameter() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GetRequestParameter() unexpected error: %v", err)
				return
			}

			if tt.wantNil {
				if param != nil {
					t.Errorf("GetRequestParameter() = %v, want nil", param)
				}
				return
			}

			if param == nil {
				t.Errorf("GetRequestParameter() = nil, want parameter")
				return
			}

			if param.Name() != tt.wantName {
				t.Errorf("GetRequestParameter() Name = %v, want %v", param.Name(), tt.wantName)
			}
			if param.Value() != tt.wantValue {
				t.Errorf("GetRequestParameter() Value = %v, want %v", param.Value(), tt.wantValue)
			}
			if param.Type() != tt.wantType {
				t.Errorf("GetRequestParameter() Type = %v, want %v", param.Type(), tt.wantType)
			}
		})
	}
}

// TestByteArrayEquals tests byte array equality.
func TestByteArrayEquals(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{
			name: "equal arrays",
			a:    []byte("hello"),
			b:    []byte("hello"),
			want: true,
		},
		{
			name: "different arrays",
			a:    []byte("hello"),
			b:    []byte("world"),
			want: false,
		},
		{
			name: "different lengths",
			a:    []byte("hello"),
			b:    []byte("hello world"),
			want: false,
		},
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "one nil",
			a:    []byte("hello"),
			b:    nil,
			want: false,
		},
		{
			name: "empty arrays",
			a:    []byte(""),
			b:    []byte(""),
			want: true,
		},
		{
			name: "case sensitive",
			a:    []byte("Hello"),
			b:    []byte("hello"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ByteArrayEquals(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("ByteArrayEquals() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestByteArrayEqualsCaseInsensitive tests case-insensitive byte array equality.
func TestByteArrayEqualsCaseInsensitive(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{
			name: "equal arrays",
			a:    []byte("hello"),
			b:    []byte("hello"),
			want: true,
		},
		{
			name: "case insensitive match",
			a:    []byte("Hello"),
			b:    []byte("hello"),
			want: true,
		},
		{
			name: "all uppercase",
			a:    []byte("HELLO"),
			b:    []byte("hello"),
			want: true,
		},
		{
			name: "mixed case",
			a:    []byte("HeLLo"),
			b:    []byte("hEllO"),
			want: true,
		},
		{
			name: "different content",
			a:    []byte("hello"),
			b:    []byte("world"),
			want: false,
		},
		{
			name: "different lengths",
			a:    []byte("hello"),
			b:    []byte("hello world"),
			want: false,
		},
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "one nil",
			a:    []byte("hello"),
			b:    nil,
			want: false,
		},
		{
			name: "HTTP header comparison",
			a:    []byte("Content-Type"),
			b:    []byte("content-type"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ByteArrayEqualsCaseInsensitive(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("ByteArrayEqualsCaseInsensitive() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestToLowerByte tests single byte lowercase conversion.
func TestToLowerByte(t *testing.T) {
	tests := []struct {
		name  string
		input byte
		want  byte
	}{
		{name: "lowercase a", input: 'a', want: 'a'},
		{name: "uppercase A", input: 'A', want: 'a'},
		{name: "lowercase z", input: 'z', want: 'z'},
		{name: "uppercase Z", input: 'Z', want: 'z'},
		{name: "digit 0", input: '0', want: '0'},
		{name: "digit 9", input: '9', want: '9'},
		{name: "space", input: ' ', want: ' '},
		{name: "dash", input: '-', want: '-'},
		{name: "underscore", input: '_', want: '_'},
		{name: "uppercase M", input: 'M', want: 'm'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToLowerByte(tt.input)
			if got != tt.want {
				t.Errorf("ToLowerByte(%c) = %c, want %c", tt.input, got, tt.want)
			}
		})
	}
}

// TestByteArrayStartsWith tests byte array prefix matching.
func TestByteArrayStartsWith(t *testing.T) {
	tests := []struct {
		name          string
		haystack      []byte
		needle        []byte
		caseSensitive bool
		offset        int
		want          bool
	}{
		{
			name:          "starts with - beginning",
			haystack:      []byte("Hello World"),
			needle:        []byte("Hello"),
			caseSensitive: true,
			offset:        0,
			want:          true,
		},
		{
			name:          "starts with - middle",
			haystack:      []byte("Hello World"),
			needle:        []byte("World"),
			caseSensitive: true,
			offset:        6,
			want:          true,
		},
		{
			name:          "does not start with",
			haystack:      []byte("Hello World"),
			needle:        []byte("World"),
			caseSensitive: true,
			offset:        0,
			want:          false,
		},
		{
			name:          "case insensitive match",
			haystack:      []byte("Hello World"),
			needle:        []byte("hello"),
			caseSensitive: false,
			offset:        0,
			want:          true,
		},
		{
			name:          "case sensitive no match",
			haystack:      []byte("Hello World"),
			needle:        []byte("hello"),
			caseSensitive: true,
			offset:        0,
			want:          false,
		},
		{
			name:          "needle too long",
			haystack:      []byte("Hi"),
			needle:        []byte("Hello"),
			caseSensitive: true,
			offset:        0,
			want:          false,
		},
		{
			name:          "empty needle",
			haystack:      []byte("Hello"),
			needle:        []byte(""),
			caseSensitive: true,
			offset:        0,
			want:          true,
		},
		{
			name:          "nil haystack",
			haystack:      nil,
			needle:        []byte("test"),
			caseSensitive: true,
			offset:        0,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ByteArrayStartsWith(tt.haystack, tt.needle, tt.caseSensitive, tt.offset)
			if got != tt.want {
				t.Errorf("ByteArrayStartsWith() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIndexOfByteInRange tests finding a single byte within a range.
func TestIndexOfByteInRange(t *testing.T) {
	tests := []struct {
		name          string
		haystack      []byte
		target        byte
		caseSensitive bool
		start         int
		end           int
		want          int
	}{
		{
			name:          "find byte at start",
			haystack:      []byte("Hello"),
			target:        'H',
			caseSensitive: true,
			start:         0,
			end:           5,
			want:          0,
		},
		{
			name:          "find byte in middle",
			haystack:      []byte("Hello"),
			target:        'l',
			caseSensitive: true,
			start:         0,
			end:           5,
			want:          2,
		},
		{
			name:          "find byte at end",
			haystack:      []byte("Hello"),
			target:        'o',
			caseSensitive: true,
			start:         0,
			end:           5,
			want:          4,
		},
		{
			name:          "byte not found",
			haystack:      []byte("Hello"),
			target:        'x',
			caseSensitive: true,
			start:         0,
			end:           5,
			want:          -1,
		},
		{
			name:          "case insensitive match",
			haystack:      []byte("Hello"),
			target:        'h',
			caseSensitive: false,
			start:         0,
			end:           5,
			want:          0,
		},
		{
			name:          "case sensitive no match",
			haystack:      []byte("Hello"),
			target:        'h',
			caseSensitive: true,
			start:         0,
			end:           5,
			want:          -1,
		},
		{
			name:          "limited range",
			haystack:      []byte("Hello"),
			target:        'o',
			caseSensitive: true,
			start:         0,
			end:           4,
			want:          -1,
		},
		{
			name:          "start from offset",
			haystack:      []byte("Hello"),
			target:        'l',
			caseSensitive: true,
			start:         3,
			end:           5,
			want:          3,
		},
		{
			name:          "nil haystack",
			haystack:      nil,
			target:        'x',
			caseSensitive: true,
			start:         0,
			end:           0,
			want:          -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IndexOfByteInRange(tt.haystack, tt.target, tt.caseSensitive, tt.start, tt.end)
			if got != tt.want {
				t.Errorf("IndexOfByteInRange() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Benchmarks

func BenchmarkIndexOf(b *testing.B) {
	haystack := []byte("Content-Type: application/json; charset=utf-8")
	needle := []byte("application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IndexOf(haystack, needle, true, 0, len(haystack))
	}
}

func BenchmarkIndexOfCaseInsensitive(b *testing.B) {
	haystack := []byte("Content-Type: APPLICATION/JSON; charset=utf-8")
	needle := []byte("application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IndexOf(haystack, needle, false, 0, len(haystack))
	}
}

func BenchmarkGetRequestParameter(b *testing.B) {
	request := []byte("GET /api?id=123&name=test&filter=active HTTP/1.1\r\n" +
		"Cookie: session=abc123; user=john\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"user=john&pass=secret")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetRequestParameter(request, "filter")
	}
}

func BenchmarkByteArrayEquals(b *testing.B) {
	a := []byte("Content-Type: application/json")
	b2 := []byte("Content-Type: application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ByteArrayEquals(a, b2)
	}
}

func BenchmarkByteArrayEqualsCaseInsensitive(b *testing.B) {
	a := []byte("Content-Type: application/json")
	b2 := []byte("content-type: APPLICATION/JSON")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ByteArrayEqualsCaseInsensitive(a, b2)
	}
}

func BenchmarkToLowerByte(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ToLowerByte('A')
	}
}

func BenchmarkByteArrayStartsWith(b *testing.B) {
	haystack := []byte("Content-Type: application/json")
	needle := []byte("Content-Type")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ByteArrayStartsWith(haystack, needle, true, 0)
	}
}

func BenchmarkIndexOfByteInRange(b *testing.B) {
	haystack := []byte("Content-Type: application/json; charset=utf-8")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IndexOfByteInRange(haystack, ':', true, 0, len(haystack))
	}
}
