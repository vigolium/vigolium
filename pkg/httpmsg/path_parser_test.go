package httpmsg

import (
	"testing"
)

// TestParsePathParameters_BasicPaths tests basic path parameter extraction.
// Ported from Burp Suite behavior validation.
func TestParsePathParameters_BasicPaths(t *testing.T) {
	tests := []struct {
		name     string
		request  string
		wantLen  int
		wantPath []struct {
			name      string
			value     string
			paramType ParamType
		}
	}{
		{
			name:    "Empty request",
			request: "",
			wantLen: 0,
		},
		{
			name:    "Root path only",
			request: "GET / HTTP/1.1\r\n",
			wantLen: 0,
		},
		{
			name:    "Single segment - folder",
			request: "GET /api/ HTTP/1.1\r\n",
			wantLen: 1,
			wantPath: []struct {
				name      string
				value     string
				paramType ParamType
			}{
				{"1", "api", ParamPathFolder},
			},
		},
		{
			name:    "Single segment - filename",
			request: "GET /api HTTP/1.1\r\n",
			wantLen: 1,
			wantPath: []struct {
				name      string
				value     string
				paramType ParamType
			}{
				{"1", "api", ParamPathFilename},
			},
		},
		{
			name:    "Two segments - both folders",
			request: "GET /api/users/ HTTP/1.1\r\n",
			wantLen: 2,
			wantPath: []struct {
				name      string
				value     string
				paramType ParamType
			}{
				{"1", "api", ParamPathFolder},
				{"2", "users", ParamPathFolder},
			},
		},
		{
			name:    "Two segments - folder and filename",
			request: "GET /api/users HTTP/1.1\r\n",
			wantLen: 2,
			wantPath: []struct {
				name      string
				value     string
				paramType ParamType
			}{
				{"1", "api", ParamPathFolder},
				{"2", "users", ParamPathFilename},
			},
		},
		{
			name:    "Multiple segments",
			request: "GET /api/v1/users/123/profile HTTP/1.1\r\n",
			wantLen: 5,
			wantPath: []struct {
				name      string
				value     string
				paramType ParamType
			}{
				{"1", "api", ParamPathFolder},
				{"2", "v1", ParamPathFolder},
				{"3", "users", ParamPathFolder},
				{"4", "123", ParamPathFolder},
				{"5", "profile", ParamPathFilename},
			},
		},
		{
			name:    "Path with query string",
			request: "GET /api/users?id=123 HTTP/1.1\r\n",
			wantLen: 2,
			wantPath: []struct {
				name      string
				value     string
				paramType ParamType
			}{
				{"1", "api", ParamPathFolder},
				{"2", "users", ParamPathFilename},
			},
		},
		{
			name:    "Path with fragment",
			request: "GET /api/users#section HTTP/1.1\r\n",
			wantLen: 2,
			wantPath: []struct {
				name      string
				value     string
				paramType ParamType
			}{
				{"1", "api", ParamPathFolder},
				{"2", "users#section", ParamPathFilename},
			},
		},
		{
			name:    "Path with trailing slash",
			request: "GET /api/users/123/ HTTP/1.1\r\n",
			wantLen: 3,
			wantPath: []struct {
				name      string
				value     string
				paramType ParamType
			}{
				{"1", "api", ParamPathFolder},
				{"2", "users", ParamPathFolder},
				{"3", "123", ParamPathFolder},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParsePathParameters([]byte(tt.request))
			if err != nil {
				t.Errorf("ParsePathParameters() error = %v", err)
				return
			}

			if len(params) != tt.wantLen {
				t.Errorf("ParsePathParameters() got %d params, want %d", len(params), tt.wantLen)
				return
			}

			for i, param := range params {
				if i >= len(tt.wantPath) {
					break
				}

				want := tt.wantPath[i]
				if param.Name() != want.name {
					t.Errorf("Parameter[%d].Name = %q, want %q", i, param.Name(), want.name)
				}
				if param.Value() != want.value {
					t.Errorf("Parameter[%d].Value = %q, want %q", i, param.Value(), want.value)
				}
				if param.Type() != want.paramType {
					t.Errorf("Parameter[%d].Type = %v, want %v", i, param.Type(), want.paramType)
				}
			}
		})
	}
}

// TestParsePathParameters_Offsets tests that byte offsets are correctly calculated.
func TestParsePathParameters_Offsets(t *testing.T) {
	request := []byte("GET /api/users/123 HTTP/1.1\r\n")
	params, err := ParsePathParameters(request)
	if err != nil {
		t.Fatalf("ParsePathParameters() error = %v", err)
	}

	if len(params) != 3 {
		t.Fatalf("ParsePathParameters() got %d params, want 3", len(params))
	}

	// Check "api" parameter offsets
	if params[0].ValueStart() != 5 || params[0].ValueEnd() != 8 {
		t.Errorf("params[0] offsets = [%d:%d], want [5:8]", params[0].ValueStart(), params[0].ValueEnd())
	}
	actualValue := string(request[params[0].ValueStart():params[0].ValueEnd()])
	if actualValue != "api" {
		t.Errorf("params[0] value at offsets = %q, want %q", actualValue, "api")
	}

	// Check "users" parameter offsets
	if params[1].ValueStart() != 9 || params[1].ValueEnd() != 14 {
		t.Errorf("params[1] offsets = [%d:%d], want [9:14]", params[1].ValueStart(), params[1].ValueEnd())
	}
	actualValue = string(request[params[1].ValueStart():params[1].ValueEnd()])
	if actualValue != "users" {
		t.Errorf("params[1] value at offsets = %q, want %q", actualValue, "users")
	}

	// Check "123" parameter offsets
	if params[2].ValueStart() != 15 || params[2].ValueEnd() != 18 {
		t.Errorf("params[2] offsets = [%d:%d], want [15:18]", params[2].ValueStart(), params[2].ValueEnd())
	}
	actualValue = string(request[params[2].ValueStart():params[2].ValueEnd()])
	if actualValue != "123" {
		t.Errorf("params[2] value at offsets = %q, want %q", actualValue, "123")
	}
}

// TestParsePathParameters_EdgeCases tests edge cases and boundary conditions.
func TestParsePathParameters_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		request string
		wantLen int
	}{
		{
			name:    "Nil request",
			request: "",
			wantLen: 0,
		},
		{
			name:    "Only HTTP method",
			request: "GET",
			wantLen: 0,
		},
		{
			name:    "Only HTTP method with space",
			request: "GET ",
			wantLen: 0,
		},
		{
			name:    "Method without path",
			request: "GET  HTTP/1.1",
			wantLen: 0,
		},
		{
			name:    "Multiple slashes",
			request: "GET /api///users HTTP/1.1\r\n",
			wantLen: 2,
		},
		{
			name:    "Path with encoded characters",
			request: "GET /api%20test/users HTTP/1.1\r\n",
			wantLen: 2,
		},
		{
			name:    "Very long path",
			request: "GET /a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p HTTP/1.1\r\n",
			wantLen: 16,
		},
		{
			name:    "Path with dots",
			request: "GET /api/users/../admin HTTP/1.1\r\n",
			wantLen: 4,
		},
		{
			name:    "Path with special chars (stopped by semicolon)",
			request: "GET /api;jsessionid=123 HTTP/1.1\r\n",
			wantLen: 1,
		},
		{
			name:    "Path with special chars (stopped by equals)",
			request: "GET /api=test HTTP/1.1\r\n",
			wantLen: 1,
		},
		{
			name:    "Path with special chars (stopped by ampersand)",
			request: "GET /api&test HTTP/1.1\r\n",
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParsePathParameters([]byte(tt.request))
			if err != nil {
				t.Errorf("ParsePathParameters() error = %v", err)
				return
			}

			if len(params) != tt.wantLen {
				t.Errorf("ParsePathParameters() got %d params, want %d", len(params), tt.wantLen)
				// Print actual params for debugging
				for i, p := range params {
					t.Logf("  param[%d]: name=%q value=%q type=%v", i, p.Name(), p.Value(), p.Type())
				}
			}
		})
	}
}

// TestParsePathParameters_RealWorldExamples tests real-world URL patterns.
func TestParsePathParameters_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name    string
		request string
		wantLen int
	}{
		{
			name:    "REST API - list resources",
			request: "GET /api/v1/users HTTP/1.1\r\n",
			wantLen: 3,
		},
		{
			name:    "REST API - get resource by ID",
			request: "GET /api/v1/users/12345 HTTP/1.1\r\n",
			wantLen: 4,
		},
		{
			name:    "REST API - nested resource",
			request: "GET /api/v1/users/12345/posts/67890 HTTP/1.1\r\n",
			wantLen: 6,
		},
		{
			name:    "REST API with query params",
			request: "GET /api/v1/users?page=1&limit=10 HTTP/1.1\r\n",
			wantLen: 3,
		},
		{
			name:    "File path",
			request: "GET /static/css/main.css HTTP/1.1\r\n",
			wantLen: 3,
		},
		{
			name:    "Deep nested path",
			request: "GET /app/admin/dashboard/settings/profile HTTP/1.1\r\n",
			wantLen: 5,
		},
		{
			name:    "GitHub-style path",
			request: "GET /repos/owner/repo/issues/123 HTTP/1.1\r\n",
			wantLen: 5,
		},
		{
			name:    "WordPress-style path",
			request: "GET /2024/01/15/blog-post-title HTTP/1.1\r\n",
			wantLen: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParsePathParameters([]byte(tt.request))
			if err != nil {
				t.Errorf("ParsePathParameters() error = %v", err)
				return
			}

			if len(params) != tt.wantLen {
				t.Errorf("ParsePathParameters() got %d params, want %d", len(params), tt.wantLen)
			}
		})
	}
}

// TestParsePathParameters_HTTPMethods tests different HTTP methods.
func TestParsePathParameters_HTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			request := method + " /api/users/123 HTTP/1.1\r\n"
			params, err := ParsePathParameters([]byte(request))
			if err != nil {
				t.Errorf("ParsePathParameters() error = %v", err)
				return
			}

			if len(params) != 3 {
				t.Errorf("ParsePathParameters() got %d params, want 3", len(params))
			}

			if len(params) > 0 && params[0].Value() != "api" {
				t.Errorf("First param value = %q, want %q", params[0].Value(), "api")
			}
		})
	}
}

// TestParsePathParameters_NameSequence tests that parameter names are sequential integers.
func TestParsePathParameters_NameSequence(t *testing.T) {
	request := []byte("GET /a/b/c/d/e HTTP/1.1\r\n")
	params, err := ParsePathParameters(request)
	if err != nil {
		t.Fatalf("ParsePathParameters() error = %v", err)
	}

	if len(params) != 5 {
		t.Fatalf("ParsePathParameters() got %d params, want 5", len(params))
	}

	expectedNames := []string{"1", "2", "3", "4", "5"}
	for i, param := range params {
		if param.Name() != expectedNames[i] {
			t.Errorf("params[%d].Name = %q, want %q", i, param.Name(), expectedNames[i])
		}
	}
}

// TestParsePathParameters_TypeClassification tests folder vs filename classification.
func TestParsePathParameters_TypeClassification(t *testing.T) {
	tests := []struct {
		name           string
		request        string
		wantLastFolder bool // true if last param should be folder, false if filename
	}{
		{
			name:           "Trailing slash - all folders",
			request:        "GET /api/users/ HTTP/1.1\r\n",
			wantLastFolder: true,
		},
		{
			name:           "No trailing slash - last is filename",
			request:        "GET /api/users HTTP/1.1\r\n",
			wantLastFolder: false,
		},
		{
			name:           "Query string - last is filename",
			request:        "GET /api/users?id=1 HTTP/1.1\r\n",
			wantLastFolder: false,
		},
		{
			name:           "Semicolon - last is filename",
			request:        "GET /api/users;param=value HTTP/1.1\r\n",
			wantLastFolder: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParsePathParameters([]byte(tt.request))
			if err != nil {
				t.Errorf("ParsePathParameters() error = %v", err)
				return
			}

			if len(params) == 0 {
				t.Fatal("No parameters extracted")
			}

			lastParam := params[len(params)-1]
			expectedType := ParamPathFilename
			if tt.wantLastFolder {
				expectedType = ParamPathFolder
			}

			if lastParam.Type() != expectedType {
				t.Errorf("Last parameter type = %v, want %v", lastParam.Type(), expectedType)
			}
		})
	}
}

// BenchmarkParsePathParameters benchmarks the path parameter parsing.
func BenchmarkParsePathParameters(b *testing.B) {
	request := []byte("GET /api/v1/users/12345/posts/67890/comments HTTP/1.1\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePathParameters(request)
	}
}

// BenchmarkParsePathParameters_LongPath benchmarks parsing a very long path.
func BenchmarkParsePathParameters_LongPath(b *testing.B) {
	request := []byte("GET /a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z HTTP/1.1\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePathParameters(request)
	}
}
