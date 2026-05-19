package httpmsg

import (
	"testing"
)

// TestAnalyzeRequest_SimpleGET tests basic GET request with query parameters
func TestAnalyzeRequest_SimpleGET(t *testing.T) {
	request := []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Verify method
	if info.Method != "GET" {
		t.Errorf("Expected method GET, got %s", info.Method)
	}

	// Verify URL
	if info.URL != "/api?id=123&name=test" {
		t.Errorf("Expected URL /api?id=123&name=test, got %s", info.URL)
	}

	// Verify HTTP version
	if info.HTTPVersion != 11 {
		t.Errorf("Expected HTTP version 11, got %d", info.HTTPVersion)
	}

	// Verify headers
	if len(info.Headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(info.Headers))
	}

	// Verify query parameters
	urlParams := info.ParametersByType(ParamURL)
	if len(urlParams) != 2 {
		t.Fatalf("Expected 2 URL parameters, got %d", len(urlParams))
	}

	// Check first parameter (id=123)
	if urlParams[0].Name() != "id" || urlParams[0].Value() != "123" {
		t.Errorf("Expected id=123, got %s=%s", urlParams[0].Name(), urlParams[0].Value())
	}

	// Check second parameter (name=test)
	if urlParams[1].Name() != "name" || urlParams[1].Value() != "test" {
		t.Errorf("Expected name=test, got %s=%s", urlParams[1].Name(), urlParams[1].Value())
	}

	// Verify no body
	if info.HasBody {
		t.Error("Expected no body for GET request")
	}

	// Verify no body parameters
	bodyParams := info.ParametersByType(ParamBody)
	if len(bodyParams) != 0 {
		t.Errorf("Expected 0 body parameters, got %d", len(bodyParams))
	}
}

// TestAnalyzeRequest_POST_URLEncoded tests POST with URL-encoded body
func TestAnalyzeRequest_POST_URLEncoded(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"\r\n" +
		"username=admin&password=secret")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Verify method
	if info.Method != "POST" {
		t.Errorf("Expected method POST, got %s", info.Method)
	}

	// Verify URL
	if info.URL != "/api" {
		t.Errorf("Expected URL /api, got %s", info.URL)
	}

	// Verify content type
	if info.ContentType != ContentTypeURLEncoded {
		t.Errorf("Expected ContentTypeURLEncoded, got %d", info.ContentType)
	}

	// Verify has body
	if !info.HasBody {
		t.Error("Expected body for POST request")
	}

	// Verify body parameters
	bodyParams := info.ParametersByType(ParamBody)
	if len(bodyParams) != 2 {
		t.Fatalf("Expected 2 body parameters, got %d", len(bodyParams))
	}

	// Check parameters
	if bodyParams[0].Name() != "username" || bodyParams[0].Value() != "admin" {
		t.Errorf("Expected username=admin, got %s=%s", bodyParams[0].Name(), bodyParams[0].Value())
	}

	if bodyParams[1].Name() != "password" || bodyParams[1].Value() != "secret" {
		t.Errorf("Expected password=secret, got %s=%s", bodyParams[1].Name(), bodyParams[1].Value())
	}
}

// TestAnalyzeRequest_POST_JSON tests POST with JSON body
func TestAnalyzeRequest_POST_JSON(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"action":"update","id":456}`)

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Verify method
	if info.Method != "POST" {
		t.Errorf("Expected method POST, got %s", info.Method)
	}

	// Verify content type
	if info.ContentType != ContentTypeJSON {
		t.Errorf("Expected ContentTypeJSON, got %d", info.ContentType)
	}

	// Verify has body
	if !info.HasBody {
		t.Error("Expected body for POST request")
	}

	// Verify JSON parameters
	jsonParams := info.ParametersByType(ParamJSON)
	if len(jsonParams) != 2 {
		t.Fatalf("Expected 2 JSON parameters, got %d", len(jsonParams))
	}

	// Check parameters (order may vary)
	foundAction := false
	foundID := false

	for _, param := range jsonParams {
		if param.Name() == "action" && param.Value() == "update" {
			foundAction = true
		}
		if param.Name() == "id" && param.Value() == "456" {
			foundID = true
		}
	}

	if !foundAction {
		t.Error("Expected to find action=update parameter")
	}
	if !foundID {
		t.Error("Expected to find id=456 parameter")
	}
}

// TestAnalyzeRequest_POST_XML tests POST with XML body
func TestAnalyzeRequest_POST_XML(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Content-Type: application/xml\r\n" +
		"\r\n" +
		`<user><name>John</name><age>30</age></user>`)

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Verify method
	if info.Method != "POST" {
		t.Errorf("Expected method POST, got %s", info.Method)
	}

	// Verify content type
	if info.ContentType != ContentTypeXML {
		t.Errorf("Expected ContentTypeXML, got %d", info.ContentType)
	}

	// Verify has body
	if !info.HasBody {
		t.Error("Expected body for POST request")
	}

	// Verify XML parameters extracted
	xmlParams := info.ParametersByType(ParamXML)
	if len(xmlParams) < 1 {
		t.Errorf("Expected at least 1 XML parameter, got %d", len(xmlParams))
	}
}

// TestAnalyzeRequest_WithCookies tests request with cookies
func TestAnalyzeRequest_WithCookies(t *testing.T) {
	request := []byte("GET /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: session=abc123; user=john\r\n" +
		"\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Verify cookie parameters
	cookieParams := info.ParametersByType(ParamCookie)
	if len(cookieParams) != 2 {
		t.Fatalf("Expected 2 cookie parameters, got %d", len(cookieParams))
	}

	// Check first cookie (session=abc123)
	if cookieParams[0].Name() != "session" || cookieParams[0].Value() != "abc123" {
		t.Errorf("Expected session=abc123, got %s=%s", cookieParams[0].Name(), cookieParams[0].Value())
	}

	// Check second cookie (user=john)
	if cookieParams[1].Name() != "user" || cookieParams[1].Value() != "john" {
		t.Errorf("Expected user=john, got %s=%s", cookieParams[1].Name(), cookieParams[1].Value())
	}
}

// TestAnalyzeRequest_Combined tests request with URL params, cookies, and body
func TestAnalyzeRequest_Combined(t *testing.T) {
	request := []byte("POST /api?filter=active HTTP/1.1\r\n" +
		"Cookie: session=abc123; user=john\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"action":"update"}`)

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Should extract all parameter types
	urlParams := info.ParametersByType(ParamURL)
	cookieParams := info.ParametersByType(ParamCookie)
	jsonParams := info.ParametersByType(ParamJSON)

	// Verify URL parameter
	if len(urlParams) != 1 {
		t.Errorf("Expected 1 URL parameter, got %d", len(urlParams))
	} else if urlParams[0].Name() != "filter" || urlParams[0].Value() != "active" {
		t.Errorf("Expected filter=active, got %s=%s", urlParams[0].Name(), urlParams[0].Value())
	}

	// Verify cookie parameters
	if len(cookieParams) != 2 {
		t.Errorf("Expected 2 cookie parameters, got %d", len(cookieParams))
	}

	// Verify JSON parameters
	if len(jsonParams) != 1 {
		t.Errorf("Expected 1 JSON parameter, got %d", len(jsonParams))
	} else if jsonParams[0].Name() != "action" || jsonParams[0].Value() != "update" {
		t.Errorf("Expected action=update, got %s=%s", jsonParams[0].Name(), jsonParams[0].Value())
	}

	// Verify path parameters
	pathParams := info.ParametersByType(ParamPathFilename)
	if len(pathParams) != 1 {
		t.Errorf("Expected 1 path parameter, got %d", len(pathParams))
	} else if pathParams[0].Name() != "1" || pathParams[0].Value() != "api" {
		t.Errorf("Expected path param 1=api, got %s=%s", pathParams[0].Name(), pathParams[0].Value())
	}

	// Total should be 5 parameters (1 URL + 1 path + 2 cookies + 1 JSON)
	if len(info.Parameters) != 5 {
		t.Errorf("Expected 5 total parameters, got %d", len(info.Parameters))
	}
}

// TestAnalyzeRequest_EmptyRequest tests empty request handling
func TestAnalyzeRequest_EmptyRequest(t *testing.T) {
	request := []byte("")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Should return empty info
	if len(info.Parameters) != 0 {
		t.Errorf("Expected 0 parameters, got %d", len(info.Parameters))
	}

	if len(info.Headers) != 0 {
		t.Errorf("Expected 0 headers, got %d", len(info.Headers))
	}
}

// TestAnalyzeRequest_NoBody tests request with no body
func TestAnalyzeRequest_NoBody(t *testing.T) {
	request := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Should not have body
	if info.HasBody {
		t.Error("Expected no body")
	}

	// Body offset should point to end
	if info.BodyOffset != len(request) {
		t.Errorf("Expected body offset %d, got %d", len(request), info.BodyOffset)
	}
}

// TestAnalyzeRequest_NoParameters tests request with no parameters
func TestAnalyzeRequest_NoParameters(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Should have no parameters
	if len(info.Parameters) != 0 {
		t.Errorf("Expected 0 parameters, got %d", len(info.Parameters))
	}
}

// TestAnalyzeRequest_Multipart tests multipart/form-data
func TestAnalyzeRequest_Multipart(t *testing.T) {
	boundary := "----WebKitFormBoundary"
	request := []byte("POST /upload HTTP/1.1\r\n" +
		"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n" +
		"\r\n" +
		"------WebKitFormBoundary\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" +
		"\r\n" +
		"file content here\r\n" +
		"------WebKitFormBoundary--\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Verify content type
	if info.ContentType != ContentTypeMultipart {
		t.Errorf("Expected ContentTypeMultipart, got %d", info.ContentType)
	}

	// Verify has body
	if !info.HasBody {
		t.Error("Expected body for multipart request")
	}

	// Should extract multipart parameters
	multipartParams := info.ParametersByType(ParamBodyMultipart)
	if len(multipartParams) < 1 {
		t.Errorf("Expected at least 1 multipart parameter, got %d", len(multipartParams))
	}
}

// TestAnalyzeRequest_HTTPVersion tests different HTTP versions
func TestAnalyzeRequest_HTTPVersion(t *testing.T) {
	tests := []struct {
		name            string
		requestLine     string
		expectedVersion int
	}{
		{
			name:            "HTTP/1.1",
			requestLine:     "GET / HTTP/1.1\r\n",
			expectedVersion: 11,
		},
		{
			name:            "HTTP/1.0",
			requestLine:     "GET / HTTP/1.0\r\n",
			expectedVersion: 10,
		},
		{
			name:            "HTTP/2.0",
			requestLine:     "GET / HTTP/2.0\r\n",
			expectedVersion: 20,
		},
		{
			name:            "HTTP/2",
			requestLine:     "GET / HTTP/2\r\n",
			expectedVersion: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.requestLine + "Host: example.com\r\n\r\n")
			info, err := AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("AnalyzeRequest failed: %v", err)
			}

			if info.HTTPVersion != tt.expectedVersion {
				t.Errorf("Expected HTTP version %d, got %d", tt.expectedVersion, info.HTTPVersion)
			}
		})
	}
}

// TestAnalyzeRequest_MultipleCookieHeaders tests multiple Cookie headers
func TestAnalyzeRequest_MultipleCookieHeaders(t *testing.T) {
	request := []byte("GET /api HTTP/1.1\r\n" +
		"Cookie: session=abc123\r\n" +
		"Cookie: user=john\r\n" +
		"Host: example.com\r\n" +
		"\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Should extract cookies from both headers
	cookieParams := info.ParametersByType(ParamCookie)
	if len(cookieParams) != 2 {
		t.Errorf("Expected 2 cookie parameters, got %d", len(cookieParams))
	}
}

// TestAnalyzeRequest_ComplexURL tests complex URL with path and query
func TestAnalyzeRequest_ComplexURL(t *testing.T) {
	request := []byte("GET /api/v1/users?id=123&sort=name&order=asc HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Verify URL extracted correctly
	if info.URL != "/api/v1/users?id=123&sort=name&order=asc" {
		t.Errorf("Expected URL /api/v1/users?id=123&sort=name&order=asc, got %s", info.URL)
	}

	// Should extract 3 query parameters
	urlParams := info.ParametersByType(ParamURL)
	if len(urlParams) != 3 {
		t.Errorf("Expected 3 URL parameters, got %d", len(urlParams))
	}
}

// TestAnalyzeRequest_CaseInsensitiveHeaders tests case-insensitive header matching
func TestAnalyzeRequest_CaseInsensitiveHeaders(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n" +
		"content-type: application/json\r\n" +
		"\r\n" +
		`{"test":"value"}`)

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Should detect JSON content type despite lowercase header
	if info.ContentType != ContentTypeJSON {
		t.Errorf("Expected ContentTypeJSON, got %d", info.ContentType)
	}
}

// TestAnalyzeRequest_GetHeader tests GetHeader helper method
func TestAnalyzeRequest_Header(t *testing.T) {
	request := []byte("GET /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: TestAgent/1.0\r\n" +
		"Accept: application/json\r\n" +
		"\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Test GetHeader method
	host := info.Header("Host")
	if host != "example.com" {
		t.Errorf("Expected Host: example.com, got %s", host)
	}

	userAgent := info.Header("User-Agent")
	if userAgent != "TestAgent/1.0" {
		t.Errorf("Expected User-Agent: TestAgent/1.0, got %s", userAgent)
	}

	accept := info.Header("Accept")
	if accept != "application/json" {
		t.Errorf("Expected Accept: application/json, got %s", accept)
	}

	// Test case-insensitive lookup
	hostLower := info.Header("host")
	if hostLower != "example.com" {
		t.Errorf("Expected case-insensitive host lookup to work, got %s", hostLower)
	}
}

// TestAnalyzeRequest_GetParameter tests GetParameter helper method
func TestAnalyzeRequest_GetParameter(t *testing.T) {
	request := []byte("GET /api?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Test GetParameter method
	idParam := info.Parameter("id")
	if idParam == nil {
		t.Fatal("Expected to find id parameter")
	}
	if idParam.Value() != "123" {
		t.Errorf("Expected id=123, got %s", idParam.Value())
	}

	nameParam := info.Parameter("name")
	if nameParam == nil {
		t.Fatal("Expected to find name parameter")
	}
	if nameParam.Value() != "test" {
		t.Errorf("Expected name=test, got %s", nameParam.Value())
	}

	// Test non-existent parameter
	missing := info.Parameter("nonexistent")
	if missing != nil {
		t.Error("Expected nil for non-existent parameter")
	}
}

// TestAnalyzeRequest_HasParameter tests HasParameter helper method
func TestAnalyzeRequest_HasParameter(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"\r\n" +
		"username=admin&password=secret")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	// Test HasParameter method
	if !info.HasParameter("username") {
		t.Error("Expected to have username parameter")
	}

	if !info.HasParameter("password") {
		t.Error("Expected to have password parameter")
	}

	if info.HasParameter("nonexistent") {
		t.Error("Expected to not have nonexistent parameter")
	}
}

// TestParseRequestLine tests request line parsing
func TestParseRequestLine(t *testing.T) {
	tests := []struct {
		name            string
		requestLine     string
		expectedMethod  string
		expectedURL     string
		expectedVersion int
	}{
		{
			name:            "Simple GET",
			requestLine:     "GET / HTTP/1.1",
			expectedMethod:  "GET",
			expectedURL:     "/",
			expectedVersion: 11,
		},
		{
			name:            "POST with path",
			requestLine:     "POST /api/users HTTP/1.1",
			expectedMethod:  "POST",
			expectedURL:     "/api/users",
			expectedVersion: 11,
		},
		{
			name:            "GET with query",
			requestLine:     "GET /search?q=test HTTP/1.1",
			expectedMethod:  "GET",
			expectedURL:     "/search?q=test",
			expectedVersion: 11,
		},
		{
			name:            "HTTP/2",
			requestLine:     "GET / HTTP/2",
			expectedMethod:  "GET",
			expectedURL:     "/",
			expectedVersion: 20,
		},
		{
			name:            "PUT request",
			requestLine:     "PUT /api/resource HTTP/1.1",
			expectedMethod:  "PUT",
			expectedURL:     "/api/resource",
			expectedVersion: 11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, url, version := parseRequestLine(tt.requestLine)

			if method != tt.expectedMethod {
				t.Errorf("Expected method %s, got %s", tt.expectedMethod, method)
			}

			if url != tt.expectedURL {
				t.Errorf("Expected URL %s, got %s", tt.expectedURL, url)
			}

			if version != tt.expectedVersion {
				t.Errorf("Expected version %d, got %d", tt.expectedVersion, version)
			}
		})
	}
}

// TestParseCookies tests cookie parsing
func TestParseCookies(t *testing.T) {
	tests := []struct {
		name           string
		cookieValue    string
		expectedCount  int
		expectedCookie map[string]string
	}{
		{
			name:          "Single cookie",
			cookieValue:   "session=abc123",
			expectedCount: 1,
			expectedCookie: map[string]string{
				"session": "abc123",
			},
		},
		{
			name:          "Multiple cookies",
			cookieValue:   "session=abc123; user=john; lang=en",
			expectedCount: 3,
			expectedCookie: map[string]string{
				"session": "abc123",
				"user":    "john",
				"lang":    "en",
			},
		},
		{
			name:          "Cookies with spaces",
			cookieValue:   "session=abc123 ; user=john ; lang=en",
			expectedCount: 3,
			expectedCookie: map[string]string{
				"session": "abc123 ",
				"user":    "john ",
				"lang":    "en",
			},
		},
		{
			name:           "Empty cookie value",
			cookieValue:    "",
			expectedCount:  0,
			expectedCookie: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := parseCookies(tt.cookieValue, 0)

			if len(params) != tt.expectedCount {
				t.Errorf("Expected %d cookies, got %d", tt.expectedCount, len(params))
			}

			// Verify cookie values
			for _, param := range params {
				if expectedValue, ok := tt.expectedCookie[param.Name()]; ok {
					if param.Value() != expectedValue {
						t.Errorf("Expected %s=%s, got %s=%s", param.Name(), expectedValue, param.Name(), param.Value())
					}
				}
			}
		})
	}
}

// TestMapContentType tests content type mapping
func TestMapContentType(t *testing.T) {
	tests := []struct {
		mimeType     string
		expectedType ContentType
	}{
		{
			mimeType:     "application/x-www-form-urlencoded",
			expectedType: ContentTypeURLEncoded,
		},
		{
			mimeType:     "multipart/form-data",
			expectedType: ContentTypeMultipart,
		},
		{
			mimeType:     "application/json",
			expectedType: ContentTypeJSON,
		},
		{
			mimeType:     "application/xml",
			expectedType: ContentTypeXML,
		},
		{
			mimeType:     "text/xml",
			expectedType: ContentTypeXML,
		},
		{
			mimeType:     "application/x-amf",
			expectedType: ContentTypeAMF,
		},
		{
			mimeType:     "text/plain",
			expectedType: ContentTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.mimeType, func(t *testing.T) {
			result := mapContentType(tt.mimeType)
			if result != tt.expectedType {
				t.Errorf("Expected %d, got %d", tt.expectedType, result)
			}
		})
	}
}
