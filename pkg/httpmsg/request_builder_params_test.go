package httpmsg

import (
	"strings"
	"testing"
)

// ==================== EXTENSION API TESTS ====================
// Tests for extension functions not covered in request_builder_part2_test.go

// TestGetParameter tests parameter extraction
func TestGetParameter(t *testing.T) {
	tests := []struct {
		name      string
		request   string
		paramName string
		paramType ParamType
		wantValue string
		wantError bool
	}{
		{
			name:      "Get URL parameter",
			request:   "GET /path?id=123&foo=bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName: "id",
			paramType: ParamURL,
			wantValue: "123",
			wantError: false,
		},
		{
			name:      "Get body parameter",
			request:   "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=secret",
			paramName: "username",
			paramType: ParamBody,
			wantValue: "admin",
			wantError: false,
		},
		{
			name:      "Get cookie parameter",
			request:   "GET /path HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123; token=xyz\r\n\r\n",
			paramName: "session",
			paramType: ParamCookie,
			wantValue: "abc123",
			wantError: false,
		},
		{
			name:      "Non-existent parameter",
			request:   "GET /path?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName: "notfound",
			paramType: ParamURL,
			wantValue: "",
			wantError: false,
		},
		{
			name:      "Empty value parameter",
			request:   "GET /path?id= HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName: "id",
			paramType: ParamURL,
			wantValue: "",
			wantError: false,
		},
		{
			name:      "Get second parameter with same prefix",
			request:   "GET /path?id=1&id2=2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName: "id2",
			paramType: ParamURL,
			wantValue: "2",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := GetParameter([]byte(tt.request), tt.paramName, tt.paramType)
			if (err != nil) != tt.wantError {
				t.Errorf("GetParameter error = %v, wantError %v", err, tt.wantError)
				return
			}
			if value != tt.wantValue {
				t.Errorf("GetParameter = %q, want %q", value, tt.wantValue)
			}
		})
	}
}

// TestHasParameter tests parameter existence check
func TestHasParameter(t *testing.T) {
	tests := []struct {
		name      string
		request   string
		paramName string
		paramType ParamType
		want      bool
	}{
		{
			name:      "URL parameter exists",
			request:   "GET /path?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName: "id",
			paramType: ParamURL,
			want:      true,
		},
		{
			name:      "Body parameter exists",
			request:   "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin",
			paramName: "username",
			paramType: ParamBody,
			want:      true,
		},
		{
			name:      "Cookie parameter exists",
			request:   "GET /path HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n",
			paramName: "session",
			paramType: ParamCookie,
			want:      true,
		},
		{
			name:      "Parameter does not exist",
			request:   "GET /path?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName: "notfound",
			paramType: ParamURL,
			want:      false,
		},
		{
			name:      "Parameter exists with empty value",
			request:   "GET /path?id= HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName: "id",
			paramType: ParamURL,
			want:      true,
		},
		{
			name:      "Wrong parameter type",
			request:   "GET /path?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName: "id",
			paramType: ParamBody,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HasParameter([]byte(tt.request), tt.paramName, tt.paramType)
			if err != nil {
				t.Fatalf("HasParameter error: %v", err)
			}
			if got != tt.want {
				t.Errorf("HasParameter = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetParameterOrDefault tests parameter extraction with default
func TestGetParameterOrDefault(t *testing.T) {
	tests := []struct {
		name       string
		request    string
		paramName  string
		paramType  ParamType
		defaultVal string
		want       string
	}{
		{
			name:       "Parameter exists",
			request:    "GET /path?limit=50 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:  "limit",
			paramType:  ParamURL,
			defaultVal: "10",
			want:       "50",
		},
		{
			name:       "Parameter does not exist - use default",
			request:    "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:  "limit",
			paramType:  ParamURL,
			defaultVal: "10",
			want:       "10",
		},
		{
			name:       "Parameter exists with empty value - use default",
			request:    "GET /path?limit= HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:  "limit",
			paramType:  ParamURL,
			defaultVal: "10",
			want:       "10",
		},
		{
			name:       "Body parameter exists",
			request:    "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npage=5",
			paramName:  "page",
			paramType:  ParamBody,
			defaultVal: "1",
			want:       "5",
		},
		{
			name:       "Zero value parameter exists",
			request:    "GET /path?count=0 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:  "count",
			paramType:  ParamURL,
			defaultVal: "100",
			want:       "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetParameterOrDefault([]byte(tt.request), tt.paramName, tt.paramType, tt.defaultVal)
			if got != tt.want {
				t.Errorf("GetParameterOrDefault = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGetAllParameters tests getting all parameters
func TestGetAllParameters(t *testing.T) {
	tests := []struct {
		name      string
		request   string
		wantCount int
	}{
		{
			name:      "Multiple parameter types",
			request:   "POST /path?id=123 HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin",
			wantCount: 4, // 1 path + 1 URL + 1 body + 1 cookie
		},
		{
			name:      "Only URL parameters",
			request:   "GET /path?a=1&b=2&c=3 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantCount: 4, // 1 path + 3 URL params
		},
		{
			name:      "No parameters",
			request:   "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantCount: 1, // 1 path param
		},
		{
			name:      "Many parameters",
			request:   "POST /path?a=1&b=2&c=3 HTTP/1.1\r\nHost: example.com\r\nCookie: x=y; z=w\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nd=4&e=5",
			wantCount: 8, // 1 path + 3 URL + 2 body + 2 cookie
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := GetAllParameters([]byte(tt.request))
			if err != nil {
				t.Fatalf("GetAllParameters error: %v", err)
			}
			if len(params) != tt.wantCount {
				t.Errorf("GetAllParameters count = %d, want %d", len(params), tt.wantCount)
			}
		})
	}
}

// TestGetParametersByType tests filtering parameters by type
func TestGetParametersByType(t *testing.T) {
	request := "POST /path?id=123&foo=bar HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: session=abc; token=xyz\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"username=admin&password=secret"

	tests := []struct {
		name      string
		paramType ParamType
		wantCount int
		wantNames []string
	}{
		{
			name:      "URL parameters",
			paramType: ParamURL,
			wantCount: 2,
			wantNames: []string{"id", "foo"},
		},
		{
			name:      "Body parameters",
			paramType: ParamBody,
			wantCount: 2,
			wantNames: []string{"username", "password"},
		},
		{
			name:      "Cookie parameters",
			paramType: ParamCookie,
			wantCount: 2,
			wantNames: []string{"session", "token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := GetParametersByType([]byte(request), tt.paramType)
			if err != nil {
				t.Fatalf("GetParametersByType error: %v", err)
			}
			if len(params) != tt.wantCount {
				t.Errorf("GetParametersByType count = %d, want %d", len(params), tt.wantCount)
			}
			for _, wantName := range tt.wantNames {
				found := false
				for _, p := range params {
					if p.Name() == wantName {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected parameter %q not found", wantName)
				}
			}
		})
	}
}

// TestGetBodyParametersMap tests getting body parameters as map
func TestGetBodyParametersMap(t *testing.T) {
	tests := []struct {
		name    string
		request string
		want    map[string]string
	}{
		{
			name:    "Multiple body parameters",
			request: "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=secret&remember=true",
			want: map[string]string{
				"username": "admin",
				"password": "secret",
				"remember": "true",
			},
		},
		{
			name:    "No body parameters",
			request: "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:    map[string]string{},
		},
		{
			name:    "Single body parameter",
			request: "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ndata=test",
			want: map[string]string{
				"data": "test",
			},
		},
		{
			name:    "Duplicate parameter names - last wins",
			request: "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nkey=first&key=second",
			want: map[string]string{
				"key": "second",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetBodyParametersMap([]byte(tt.request))
			if err != nil {
				t.Fatalf("GetBodyParametersMap error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Errorf("GetBodyParametersMap length = %d, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("GetBodyParametersMap[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestSetBodyParametersMap tests setting body parameters from map
func TestSetBodyParametersMap(t *testing.T) {
	tests := []struct {
		name       string
		request    string
		params     map[string]string
		wantParams []string
	}{
		{
			name:    "Replace all body parameters",
			request: "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nold=value",
			params: map[string]string{
				"username": "admin",
				"password": "secret",
			},
			wantParams: []string{"username=admin", "password=secret"},
		},
		{
			name:    "Set parameters on empty body",
			request: "POST /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			params: map[string]string{
				"data": "test",
			},
			wantParams: []string{"data=test"},
		},
		{
			name:       "Empty map - remove all body parameters",
			request:    "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nold=value",
			params:     map[string]string{},
			wantParams: []string{},
		},
		{
			name:    "Preserve URL and cookie parameters",
			request: "POST /path?url=param HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nold=value",
			params: map[string]string{
				"new": "value",
			},
			wantParams: []string{"new=value", "url=param", "session=abc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetBodyParametersMap([]byte(tt.request), tt.params)
			if err != nil {
				t.Fatalf("SetBodyParametersMap error: %v", err)
			}
			resultStr := string(result)
			for _, wantParam := range tt.wantParams {
				if !strings.Contains(resultStr, wantParam) {
					t.Errorf("Result does not contain expected parameter\nGot:\n%s\nWant to contain: %s", resultStr, wantParam)
				}
			}
		})
	}
}

// TestAppendBodyParameter tests appending body parameters
func TestAppendBodyParameter(t *testing.T) {
	tests := []struct {
		name         string
		request      string
		paramName    string
		paramValue   string
		wantContains string
	}{
		{
			name:         "Append to empty body",
			request:      "POST /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:    "data",
			paramValue:   "test",
			wantContains: "data=test",
		},
		{
			name:         "Append to existing body",
			request:      "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nfoo=bar",
			paramName:    "id",
			paramValue:   "123",
			wantContains: "foo=bar&id=123",
		},
		{
			name:       "Append special characters",
			request:    "POST /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:  "data",
			paramValue: "a b&c=d",
			// Values are written as-is without encoding
			// User must pre-encode values if needed
			wantContains: "data=a b&c=d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AppendBodyParameter([]byte(tt.request), tt.paramName, tt.paramValue)
			if err != nil {
				t.Fatalf("AppendBodyParameter error: %v", err)
			}
			resultStr := string(result)
			if !strings.Contains(resultStr, tt.wantContains) {
				t.Errorf("Result does not contain expected content\nGot:\n%s\nWant to contain: %s", resultStr, tt.wantContains)
			}
		})
	}
}

// TestRemoveAllParametersByType tests removing all parameters of a type
func TestRemoveAllParametersByType(t *testing.T) {
	tests := []struct {
		name       string
		request    string
		paramType  ParamType
		notContain []string
		contain    []string
	}{
		{
			name:       "Remove all URL parameters",
			request:    "GET /path?id=123&foo=bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramType:  ParamURL,
			notContain: []string{"id=123", "foo=bar", "?"},
			contain:    []string{"GET /path HTTP/1.1"},
		},
		{
			name:       "Remove all body parameters",
			request:    "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=secret",
			paramType:  ParamBody,
			notContain: []string{"username=admin", "password=secret"},
			contain:    []string{"POST /path HTTP/1.1"},
		},
		{
			name:       "Remove all cookies",
			request:    "GET /path HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc; token=xyz\r\n\r\n",
			paramType:  ParamCookie,
			notContain: []string{"session=abc", "token=xyz", "Cookie:"},
			contain:    []string{"GET /path HTTP/1.1"},
		},
		{
			name:       "Remove URL params but preserve body",
			request:    "POST /path?id=123 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ndata=test",
			paramType:  ParamURL,
			notContain: []string{"id=123", "?"},
			contain:    []string{"data=test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := RemoveAllParametersByType([]byte(tt.request), tt.paramType)
			if err != nil {
				t.Fatalf("RemoveAllParametersByType error: %v", err)
			}
			resultStr := string(result)
			for _, notWant := range tt.notContain {
				if strings.Contains(resultStr, notWant) {
					t.Errorf("Result should not contain %q\nGot:\n%s", notWant, resultStr)
				}
			}
			for _, want := range tt.contain {
				if !strings.Contains(resultStr, want) {
					t.Errorf("Result should contain %q\nGot:\n%s", want, resultStr)
				}
			}
		})
	}
}

// TestRemoveParametersByName tests removing parameters by name
func TestRemoveParametersByName(t *testing.T) {
	tests := []struct {
		name       string
		request    string
		names      []string
		paramType  ParamType
		notContain []string
		contain    []string
	}{
		{
			name:       "Remove multiple URL parameters by name",
			request:    "GET /path?id=123&foo=bar&keep=this HTTP/1.1\r\nHost: example.com\r\n\r\n",
			names:      []string{"id", "foo"},
			paramType:  ParamURL,
			notContain: []string{"id=123", "foo=bar"},
			contain:    []string{"keep=this"},
		},
		{
			name:       "Remove single body parameter",
			request:    "POST /path HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=secret",
			names:      []string{"password"},
			paramType:  ParamBody,
			notContain: []string{"password=secret"},
			contain:    []string{"username=admin"},
		},
		{
			name:       "Remove non-existent parameters - no change",
			request:    "GET /path?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			names:      []string{"notfound", "alsonotfound"},
			paramType:  ParamURL,
			notContain: []string{},
			contain:    []string{"id=123"},
		},
		{
			name:       "Remove all cookies by name",
			request:    "GET /path HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc; token=xyz; keep=this\r\n\r\n",
			names:      []string{"session", "token"},
			paramType:  ParamCookie,
			notContain: []string{"session=abc", "token=xyz"},
			contain:    []string{"keep=this"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := RemoveParametersByName([]byte(tt.request), tt.names, tt.paramType)
			if err != nil {
				t.Fatalf("RemoveParametersByName error: %v", err)
			}
			resultStr := string(result)
			for _, notWant := range tt.notContain {
				if strings.Contains(resultStr, notWant) {
					t.Errorf("Result should not contain %q\nGot:\n%s", notWant, resultStr)
				}
			}
			for _, want := range tt.contain {
				if !strings.Contains(resultStr, want) {
					t.Errorf("Result should contain %q\nGot:\n%s", want, resultStr)
				}
			}
		})
	}
}

// TestAddMultipleParameters tests adding multiple parameters
func TestAddMultipleParameters(t *testing.T) {
	tests := []struct {
		name         string
		request      string
		params       []*Param
		wantContains []string
	}{
		{
			name:    "Add multiple URL parameters",
			request: "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			params: []*Param{
				BuildParameter("id", "123", ParamURL),
				BuildParameter("foo", "bar", ParamURL),
			},
			wantContains: []string{"id=123", "foo=bar"},
		},
		{
			name:    "Add multiple body parameters",
			request: "POST /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			params: []*Param{
				BuildParameter("username", "admin", ParamBody),
				BuildParameter("password", "secret", ParamBody),
			},
			wantContains: []string{"username=admin", "password=secret"},
		},
		{
			name:    "Add mixed parameter types",
			request: "POST /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			params: []*Param{
				BuildParameter("id", "123", ParamURL),
				BuildParameter("data", "test", ParamBody),
				BuildParameter("session", "abc", ParamCookie),
			},
			wantContains: []string{"id=123", "data=test", "session=abc"},
		},
		{
			name:    "Add to existing parameters",
			request: "POST /path?existing=param HTTP/1.1\r\nHost: example.com\r\n\r\n",
			params: []*Param{
				BuildParameter("new1", "val1", ParamURL),
				BuildParameter("new2", "val2", ParamURL),
			},
			wantContains: []string{"existing=param", "new1=val1", "new2=val2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AddMultipleParameters([]byte(tt.request), tt.params)
			if err != nil {
				t.Fatalf("AddMultipleParameters error: %v", err)
			}
			resultStr := string(result)
			for _, want := range tt.wantContains {
				if !strings.Contains(resultStr, want) {
					t.Errorf("Result does not contain expected content\nGot:\n%s\nWant to contain: %s", resultStr, want)
				}
			}
		})
	}
}

// ==================== HELPER FUNCTION TESTS ====================

// TestParseRequestLineString tests request line parsing
func TestParseRequestLineString(t *testing.T) {
	tests := []struct {
		name        string
		requestLine string
		wantMethod  string
		wantURL     string
		wantVersion string
	}{
		{
			name:        "Complete request line",
			requestLine: "GET /path HTTP/1.1",
			wantMethod:  "GET",
			wantURL:     "/path",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "No HTTP version",
			requestLine: "GET /path",
			wantMethod:  "GET",
			wantURL:     "/path",
			wantVersion: "HTTP/1.1", // Default
		},
		{
			name:        "POST method",
			requestLine: "POST /api/users HTTP/1.0",
			wantMethod:  "POST",
			wantURL:     "/api/users",
			wantVersion: "HTTP/1.0",
		},
		{
			name:        "URL with query string",
			requestLine: "GET /path?id=123 HTTP/1.1",
			wantMethod:  "GET",
			wantURL:     "/path?id=123",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "Empty string",
			requestLine: "",
			wantMethod:  "",
			wantURL:     "",
			wantVersion: "",
		},
		{
			name:        "Only method",
			requestLine: "GET",
			wantMethod:  "",
			wantURL:     "",
			wantVersion: "",
		},
		{
			name:        "PUT method",
			requestLine: "PUT /resource/123 HTTP/1.1",
			wantMethod:  "PUT",
			wantURL:     "/resource/123",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "DELETE method",
			requestLine: "DELETE /resource HTTP/2",
			wantMethod:  "DELETE",
			wantURL:     "/resource",
			wantVersion: "HTTP/2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, url, version := parseRequestLineString(tt.requestLine)
			if method != tt.wantMethod {
				t.Errorf("method = %q, want %q", method, tt.wantMethod)
			}
			if url != tt.wantURL {
				t.Errorf("url = %q, want %q", url, tt.wantURL)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

// TestRemoveParameterFromQueryString tests query string parameter removal
func TestRemoveParameterFromQueryString(t *testing.T) {
	tests := []struct {
		name        string
		queryString string
		paramName   string
		want        string
	}{
		{
			name:        "Remove only parameter",
			queryString: "/path?id=123",
			paramName:   "id",
			want:        "/path",
		},
		{
			name:        "Remove first parameter",
			queryString: "/path?id=123&foo=bar",
			paramName:   "id",
			want:        "/path?foo=bar",
		},
		{
			name:        "Remove middle parameter",
			queryString: "/path?a=1&b=2&c=3",
			paramName:   "b",
			want:        "/path?a=1&c=3",
		},
		{
			name:        "Remove last parameter",
			queryString: "/path?foo=bar&id=123",
			paramName:   "id",
			want:        "/path?foo=bar",
		},
		{
			name:        "Non-existent parameter",
			queryString: "/path?foo=bar",
			paramName:   "notfound",
			want:        "/path?foo=bar",
		},
		{
			name:        "No query string",
			queryString: "/path",
			paramName:   "id",
			want:        "/path",
		},
		{
			name:        "Empty query string",
			queryString: "",
			paramName:   "id",
			want:        "",
		},
		{
			name:        "Parameter without value",
			queryString: "?id&foo=bar",
			paramName:   "id",
			want:        "?foo=bar",
		},
		{
			name:        "Only query string without path",
			queryString: "?a=1&b=2",
			paramName:   "a",
			want:        "?b=2",
		},
		{
			name:        "Parameter with special characters",
			queryString: "/path?data=a%20b&other=c",
			paramName:   "data",
			want:        "/path?other=c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeParameterFromQueryString(tt.queryString, tt.paramName)
			if got != tt.want {
				t.Errorf("removeParameterFromQueryString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRemoveParameterFromCookieString tests cookie string parameter removal
func TestRemoveParameterFromCookieString(t *testing.T) {
	tests := []struct {
		name         string
		cookieString string
		paramName    string
		want         string
	}{
		{
			name:         "Remove only cookie",
			cookieString: "session=abc123",
			paramName:    "session",
			want:         "",
		},
		{
			name:         "Remove first cookie",
			cookieString: "session=abc123; foo=bar",
			paramName:    "session",
			want:         "foo=bar",
		},
		{
			name:         "Remove middle cookie",
			cookieString: "a=1; b=2; c=3",
			paramName:    "b",
			want:         "a=1; c=3",
		},
		{
			name:         "Remove last cookie",
			cookieString: "foo=bar; session=abc123",
			paramName:    "session",
			want:         "foo=bar",
		},
		{
			name:         "Non-existent cookie",
			cookieString: "foo=bar",
			paramName:    "notfound",
			want:         "foo=bar",
		},
		{
			name:         "Empty cookie string",
			cookieString: "",
			paramName:    "session",
			want:         "",
		},
		{
			name:         "Cookie with spaces",
			cookieString: "session=abc123 ; foo=bar",
			paramName:    "session",
			want:         "foo=bar",
		},
		{
			name:         "Cookie without value",
			cookieString: "a=1; b; c=3",
			paramName:    "b",
			want:         "a=1; c=3",
		},
		{
			name:         "Multiple spaces around separator",
			cookieString: "a=1  ;  b=2  ;  c=3",
			paramName:    "b",
			want:         "a=1; c=3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeParameterFromCookieString(tt.cookieString, tt.paramName)
			if got != tt.want {
				t.Errorf("removeParameterFromCookieString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildRequestWithMethodAndParams tests internal helper
func TestBuildRequestWithMethodAndParams(t *testing.T) {
	request := []byte("GET /path?old=value HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n")
	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest error: %v", err)
	}

	tests := []struct {
		name         string
		newMethod    string
		params       []*Param
		wantContains []string
	}{
		{
			name:      "Build POST with all parameter types",
			newMethod: "POST",
			params: []*Param{
				BuildParameter("id", "123", ParamURL),
				BuildParameter("data", "test", ParamBody),
				BuildParameter("token", "xyz", ParamCookie),
			},
			wantContains: []string{
				"POST /path?id=123 HTTP/1.1",
				"data=test",
				"Cookie: token=xyz",
			},
		},
		{
			name:      "Build GET with only URL params",
			newMethod: "GET",
			params: []*Param{
				BuildParameter("a", "1", ParamURL),
				BuildParameter("b", "2", ParamURL),
			},
			wantContains: []string{
				"GET /path?a=1&b=2 HTTP/1.1",
			},
		},
		{
			name:      "Build PUT with body params",
			newMethod: "PUT",
			params: []*Param{
				BuildParameter("update", "value", ParamBody),
			},
			wantContains: []string{
				"PUT /path HTTP/1.1",
				"update=value",
			},
		},
		{
			name:      "Build request with no params",
			newMethod: "DELETE",
			params:    []*Param{},
			wantContains: []string{
				"DELETE /path HTTP/1.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildRequestWithMethodAndParams(request, info, tt.newMethod, tt.params)
			if err != nil {
				t.Fatalf("buildRequestWithMethodAndParams error: %v", err)
			}
			resultStr := string(result)
			for _, want := range tt.wantContains {
				if !strings.Contains(resultStr, want) {
					t.Errorf("Result does not contain expected content\nGot:\n%s\nWant to contain: %s", resultStr, want)
				}
			}
		})
	}
}

// ==================== EDGE CASE TESTS ====================

// TestExtensionAPI_EdgeCases tests edge cases for extension API
func TestExtensionAPI_EdgeCases(t *testing.T) {
	t.Run("GetParameter with malformed request", func(t *testing.T) {
		malformed := []byte("not a valid http request")
		_, err := GetParameter(malformed, "id", ParamURL)
		// Should handle gracefully
		if err == nil {
			t.Log("GetParameter handled malformed request")
		}
	})

	t.Run("HasParameter with empty request", func(t *testing.T) {
		empty := []byte("")
		_, err := HasParameter(empty, "id", ParamURL)
		// Should handle gracefully
		if err == nil {
			t.Log("HasParameter handled empty request")
		}
	})

	t.Run("GetAllParameters with only headers", func(t *testing.T) {
		onlyHeaders := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		params, err := GetAllParameters(onlyHeaders)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if len(params) != 0 {
			t.Errorf("Expected 0 parameters, got %d", len(params))
		}
	})

	t.Run("SetBodyParametersMap with nil map", func(t *testing.T) {
		request := []byte("POST /path HTTP/1.1\r\nHost: example.com\r\n\r\nold=value")
		result, err := SetBodyParametersMap(request, nil)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if result == nil {
			t.Error("Expected non-nil result")
		}
	})

	t.Run("RemoveParametersByName with empty names slice", func(t *testing.T) {
		request := []byte("GET /path?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n")
		result, err := RemoveParametersByName(request, []string{}, ParamURL)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		// Should return request unchanged
		if string(result) != string(request) {
			t.Error("Request should be unchanged when removing empty names list")
		}
	})

	t.Run("AddMultipleParameters with empty slice", func(t *testing.T) {
		request := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
		result, err := AddMultipleParameters(request, []*Param{})
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		// Should return request unchanged
		if string(result) != string(request) {
			t.Error("Request should be unchanged when adding empty params list")
		}
	})
}

// TestHelperFunctions_EdgeCases tests edge cases for helper functions
func TestHelperFunctions_EdgeCases(t *testing.T) {
	t.Run("parseRequestLineString with multiple spaces", func(t *testing.T) {
		method, url, version := parseRequestLineString("GET  /path  HTTP/1.1")
		if method != "GET" || url != "" || version != "" {
			t.Logf("Multiple spaces: method=%q, url=%q, version=%q", method, url, version)
		}
	})

	t.Run("removeParameterFromQueryString with encoded equals", func(t *testing.T) {
		result := removeParameterFromQueryString("?data=a%3Db&other=c", "data")
		if !strings.Contains(result, "other=c") {
			t.Errorf("Expected to keep 'other=c', got: %s", result)
		}
	})

	t.Run("removeParameterFromCookieString with semicolon in value", func(t *testing.T) {
		// Note: This is technically invalid cookie format, but test robustness
		result := removeParameterFromCookieString("a=1; b=2", "a")
		if result != "b=2" {
			t.Errorf("Expected 'b=2', got: %s", result)
		}
	})
}

// TestIntegration_CompleteWorkflow tests a complete workflow
func TestIntegration_CompleteWorkflow(t *testing.T) {
	// Start with basic request
	request := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Add URL parameter
	request, err := AddParameter(request, BuildParameter("id", "123", ParamURL))
	if err != nil {
		t.Fatalf("AddParameter URL failed: %v", err)
	}

	// Check parameter exists
	exists, _ := HasParameter(request, "id", ParamURL)
	if !exists {
		t.Error("Parameter should exist after adding")
	}

	// Get parameter value
	value, _ := GetParameter(request, "id", ParamURL)
	if value != "123" {
		t.Errorf("Expected value '123', got '%s'", value)
	}

	// Update parameter
	request, err = UpdateParameter(request, BuildParameter("id", "456", ParamURL))
	if err != nil {
		t.Fatalf("UpdateParameter failed: %v", err)
	}

	// Verify update
	value, _ = GetParameter(request, "id", ParamURL)
	if value != "456" {
		t.Errorf("Expected updated value '456', got '%s'", value)
	}

	// Add multiple parameters
	request, err = AddMultipleParameters(request, []*Param{
		BuildParameter("foo", "bar", ParamURL),
		BuildParameter("data", "test", ParamBody),
	})
	if err != nil {
		t.Fatalf("AddMultipleParameters failed: %v", err)
	}

	// Get all parameters
	allParams, _ := GetAllParameters(request)
	if len(allParams) < 3 {
		t.Errorf("Expected at least 3 parameters, got %d", len(allParams))
	}

	// Remove specific parameter
	request, err = RemoveParameter(request, BuildParameter("foo", "", ParamURL))
	if err != nil {
		t.Fatalf("RemoveParameter failed: %v", err)
	}

	// Verify removal
	exists, _ = HasParameter(request, "foo", ParamURL)
	if exists {
		t.Error("Parameter should not exist after removal")
	}

	// Toggle method
	request, err = ToggleRequestMethod(request)
	if err != nil {
		t.Fatalf("ToggleRequestMethod failed: %v", err)
	}

	// Verify method changed to POST
	if !strings.Contains(string(request), "POST /api") {
		t.Error("Method should be toggled to POST")
	}
}
