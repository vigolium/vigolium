package httpmsg

import (
	"testing"
)

// =============================================================================
// ENCODING INTEGRATION TESTS
// =============================================================================
// These tests verify the full encode/decode pipeline:
// 1. AnalyzeRequest() parses and decodes parameters
// 2. NewParameterInsertionPoint() creates IP from parsed param
// 3. InsertionPoint.BuildRequest() re-encodes payloads correctly
//
// Tests use EXACT raw request comparison for precision.
//
// RFC 3986 Encoding Rules:
// - Query/Body/Cookie: space ↔ '+', special chars ↔ '%XX'
// - Path: space → '%20' (NOT '+'), '+' stays literal, special chars → '%XX'
// =============================================================================

// TestQueryEncodingPipeline tests the full query parameter encode/decode cycle.
func TestQueryEncodingPipeline(t *testing.T) {
	tests := []struct {
		name            string
		request         string
		paramName       string
		expectedValue   string // Decoded value from AnalyzeRequest
		injectPayload   string
		expectedRequest string // Exact raw request after injection
	}{
		{
			name:            "plus decoded to space",
			request:         "GET /api?name=hello+world HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:       "name",
			expectedValue:   "hello world",
			injectPayload:   "test value",
			expectedRequest: "GET /api?name=test+value HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:            "percent20 decoded to space",
			request:         "GET /api?name=hello%20world HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:       "name",
			expectedValue:   "hello world",
			injectPayload:   "foo bar",
			expectedRequest: "GET /api?name=foo+bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:            "percent2B decoded to plus",
			request:         "GET /api?expr=1%2B2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:       "expr",
			expectedValue:   "1+2",
			injectPayload:   "a+b",
			expectedRequest: "GET /api?expr=a%2Bb HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:            "special chars decoded",
			request:         "GET /api?q=a%26b%3Dc HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:       "q",
			expectedValue:   "a&b=c",
			injectPayload:   "x&y=z",
			expectedRequest: "GET /api?q=x%26y%3Dz HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:            "unreserved chars pass through",
			request:         "GET /api?id=abc-123_test.txt~v1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			paramName:       "id",
			expectedValue:   "abc-123_test.txt~v1",
			injectPayload:   "new-file_2.txt~v2",
			expectedRequest: "GET /api?id=new-file_2.txt~v2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			info, err := AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("AnalyzeRequest() error = %v", err)
			}

			var param *Param
			for _, p := range info.Parameters {
				if p.Name() == tt.paramName && p.Type() == ParamURL {
					param = p
					break
				}
			}
			if param == nil {
				t.Fatalf("Parameter %q not found", tt.paramName)
			}

			if param.Value() != tt.expectedValue {
				t.Errorf("Decoded value = %q, want %q", param.Value(), tt.expectedValue)
			}

			ip := NewParameterInsertionPoint(request, param)
			result := ip.BuildRequest([]byte(tt.injectPayload))

			if string(result) != tt.expectedRequest {
				t.Errorf("BuildRequest mismatch:\ngot:  %q\nwant: %q", string(result), tt.expectedRequest)
			}
		})
	}
}

// TestPathEncodingPipeline tests the full path parameter encode/decode cycle.
// Path uses RFC 3986: space → '%20' (NOT '+'), '+' stays literal.
func TestPathEncodingPipeline(t *testing.T) {
	tests := []struct {
		name            string
		request         string
		segmentIndex    int
		expectedValue   string
		injectPayload   string
		expectedRequest string
	}{
		{
			name:            "plus stays literal in path",
			request:         "GET /api/v1+2/data HTTP/1.1\r\nHost: example.com\r\n\r\n",
			segmentIndex:    2,
			expectedValue:   "v1+2", // + stays literal (RFC 3986)
			injectPayload:   "v2+3",
			expectedRequest: "GET /api/v2%2B3/data HTTP/1.1\r\nHost: example.com\r\n\r\n", // + → %2B
		},
		{
			name:            "percent20 decoded to space in path",
			request:         "GET /api/hello%20world/data HTTP/1.1\r\nHost: example.com\r\n\r\n",
			segmentIndex:    2,
			expectedValue:   "hello world",
			injectPayload:   "foo bar",
			expectedRequest: "GET /api/foo%20bar/data HTTP/1.1\r\nHost: example.com\r\n\r\n", // space → %20
		},
		{
			name:            "slash encoded in path segment",
			request:         "GET /api/user%2Fadmin/profile HTTP/1.1\r\nHost: example.com\r\n\r\n",
			segmentIndex:    2,
			expectedValue:   "user/admin",
			injectPayload:   "test/path",
			expectedRequest: "GET /api/test%2Fpath/profile HTTP/1.1\r\nHost: example.com\r\n\r\n", // / → %2F
		},
		{
			name:            "special chars in path",
			request:         "GET /api/a%26b%3Dc/data HTTP/1.1\r\nHost: example.com\r\n\r\n",
			segmentIndex:    2,
			expectedValue:   "a&b=c",
			injectPayload:   "x&y=z",
			expectedRequest: "GET /api/x%26y%3Dz/data HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:            "path filename encoding",
			request:         "GET /api/users/profile.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
			segmentIndex:    3,
			expectedValue:   "profile.html",
			injectPayload:   "my file.txt",
			expectedRequest: "GET /api/users/my%20file.txt HTTP/1.1\r\nHost: example.com\r\n\r\n", // space → %20
		},
		{
			name:            "unreserved chars in path",
			request:         "GET /api/test-file_v1.txt~backup HTTP/1.1\r\nHost: example.com\r\n\r\n",
			segmentIndex:    2,
			expectedValue:   "test-file_v1.txt~backup",
			injectPayload:   "new-file_v2.txt~latest",
			expectedRequest: "GET /api/new-file_v2.txt~latest HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			info, err := AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("AnalyzeRequest() error = %v", err)
			}

			var param *Param
			segmentName := intToString(tt.segmentIndex)
			for _, p := range info.Parameters {
				if p.Name() == segmentName && (p.Type() == ParamPathFolder || p.Type() == ParamPathFilename) {
					param = p
					break
				}
			}
			if param == nil {
				t.Fatalf("Path segment %d not found", tt.segmentIndex)
			}

			if param.Value() != tt.expectedValue {
				t.Errorf("Decoded value = %q, want %q", param.Value(), tt.expectedValue)
			}

			ip := NewParameterInsertionPoint(request, param)
			result := ip.BuildRequest([]byte(tt.injectPayload))

			if string(result) != tt.expectedRequest {
				t.Errorf("BuildRequest mismatch:\ngot:  %q\nwant: %q", string(result), tt.expectedRequest)
			}
		})
	}
}

// TestCookieEncodingPipeline tests the full cookie parameter encode/decode cycle.
func TestCookieEncodingPipeline(t *testing.T) {
	tests := []struct {
		name            string
		request         string
		cookieName      string
		expectedValue   string
		injectPayload   string
		expectedRequest string
	}{
		{
			name:            "plus decoded to space in cookie",
			request:         "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=hello+world\r\n\r\n",
			cookieName:      "session",
			expectedValue:   "hello world",
			injectPayload:   "test value",
			expectedRequest: "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=test+value\r\n\r\n",
		},
		{
			name:            "percent20 decoded to space in cookie",
			request:         "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: data=hello%20world\r\n\r\n",
			cookieName:      "data",
			expectedValue:   "hello world",
			injectPayload:   "foo bar",
			expectedRequest: "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: data=foo+bar\r\n\r\n",
		},
		{
			name:            "special chars in cookie",
			request:         "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: token=a%3Db%26c\r\n\r\n",
			cookieName:      "token",
			expectedValue:   "a=b&c",
			injectPayload:   "x=y&z",
			expectedRequest: "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: token=x%3Dy%26z\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			info, err := AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("AnalyzeRequest() error = %v", err)
			}

			var param *Param
			for _, p := range info.Parameters {
				if p.Name() == tt.cookieName && p.Type() == ParamCookie {
					param = p
					break
				}
			}
			if param == nil {
				t.Fatalf("Cookie %q not found", tt.cookieName)
			}

			if param.Value() != tt.expectedValue {
				t.Errorf("Decoded value = %q, want %q", param.Value(), tt.expectedValue)
			}

			ip := NewParameterInsertionPoint(request, param)
			result := ip.BuildRequest([]byte(tt.injectPayload))

			if string(result) != tt.expectedRequest {
				t.Errorf("BuildRequest mismatch:\ngot:  %q\nwant: %q", string(result), tt.expectedRequest)
			}
		})
	}
}

// TestBodyEncodingPipeline tests URL-encoded body parameter encode/decode cycle.
func TestBodyEncodingPipeline(t *testing.T) {
	tests := []struct {
		name            string
		request         string
		paramName       string
		expectedValue   string
		injectPayload   string
		expectedRequest string
	}{
		{
			name:            "plus decoded to space in body",
			request:         "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 16\r\n\r\nname=hello+world",
			paramName:       "name",
			expectedValue:   "hello world",
			injectPayload:   "test value",
			expectedRequest: "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nname=test+value",
		},
		{
			name:            "special chars in body",
			request:         "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 14\r\n\r\ndata=a%26b%3Dc",
			paramName:       "data",
			expectedValue:   "a&b=c",
			injectPayload:   "x&y=z",
			expectedRequest: "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 14\r\n\r\ndata=x%26y%3Dz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			info, err := AnalyzeRequest(request)
			if err != nil {
				t.Fatalf("AnalyzeRequest() error = %v", err)
			}

			var param *Param
			for _, p := range info.Parameters {
				if p.Name() == tt.paramName && p.Type() == ParamBody {
					param = p
					break
				}
			}
			if param == nil {
				t.Fatalf("Body parameter %q not found", tt.paramName)
			}

			if param.Value() != tt.expectedValue {
				t.Errorf("Decoded value = %q, want %q", param.Value(), tt.expectedValue)
			}

			ip := NewParameterInsertionPoint(request, param)
			result := ip.BuildRequest([]byte(tt.injectPayload))

			if string(result) != tt.expectedRequest {
				t.Errorf("BuildRequest mismatch:\ngot:  %q\nwant: %q", string(result), tt.expectedRequest)
			}
		})
	}
}

// TestQueryVsPathEncodingDifference verifies query uses '+' and path uses '%20' for space.
func TestQueryVsPathEncodingDifference(t *testing.T) {
	request := []byte("GET /api/hello%20world/data?name=hello+world HTTP/1.1\r\nHost: example.com\r\n\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest() error = %v", err)
	}

	var pathParam, queryParam *Param
	for _, p := range info.Parameters {
		if (p.Type() == ParamPathFolder || p.Type() == ParamPathFilename) && p.Value() == "hello world" {
			pathParam = p
		}
		if p.Type() == ParamURL && p.Name() == "name" {
			queryParam = p
		}
	}

	if pathParam == nil {
		t.Fatal("Path parameter not found")
	}
	if queryParam == nil {
		t.Fatal("Query parameter not found")
	}

	// Both decode to "hello world"
	if pathParam.Value() != "hello world" {
		t.Errorf("Path param = %q, want 'hello world'", pathParam.Value())
	}
	if queryParam.Value() != "hello world" {
		t.Errorf("Query param = %q, want 'hello world'", queryParam.Value())
	}

	// Inject "test value" - path uses %20, query uses +
	payload := []byte("test value")

	pathIP := NewParameterInsertionPoint(request, pathParam)
	pathResult := pathIP.BuildRequest(payload)
	expectedPathResult := "GET /api/test%20value/data?name=hello+world HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(pathResult) != expectedPathResult {
		t.Errorf("Path injection mismatch:\ngot:  %q\nwant: %q", string(pathResult), expectedPathResult)
	}

	queryIP := NewParameterInsertionPoint(request, queryParam)
	queryResult := queryIP.BuildRequest(payload)
	expectedQueryResult := "GET /api/hello%20world/data?name=test+value HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(queryResult) != expectedQueryResult {
		t.Errorf("Query injection mismatch:\ngot:  %q\nwant: %q", string(queryResult), expectedQueryResult)
	}
}

// TestPlusLiteralInPath verifies '+' in path stays literal (not decoded to space).
func TestPlusLiteralInPath(t *testing.T) {
	request := []byte("GET /api/v1+2/data HTTP/1.1\r\nHost: example.com\r\n\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest() error = %v", err)
	}

	var pathParam *Param
	for _, p := range info.Parameters {
		if (p.Type() == ParamPathFolder || p.Type() == ParamPathFilename) && p.Name() == "2" {
			pathParam = p
			break
		}
	}
	if pathParam == nil {
		t.Fatal("Path parameter not found")
	}

	// + stays literal in path (RFC 3986)
	if pathParam.Value() != "v1+2" {
		t.Errorf("Path value = %q, want 'v1+2'", pathParam.Value())
	}

	// Inject "v2+3" - + must be encoded as %2B
	ip := NewParameterInsertionPoint(request, pathParam)
	result := ip.BuildRequest([]byte("v2+3"))
	expected := "GET /api/v2%2B3/data HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(result) != expected {
		t.Errorf("BuildRequest mismatch:\ngot:  %q\nwant: %q", string(result), expected)
	}
}

// TestPlusDecodedInQuery verifies '+' in query is decoded to space.
func TestPlusDecodedInQuery(t *testing.T) {
	request := []byte("GET /api?name=hello+world HTTP/1.1\r\nHost: example.com\r\n\r\n")

	info, err := AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest() error = %v", err)
	}

	var queryParam *Param
	for _, p := range info.Parameters {
		if p.Type() == ParamURL && p.Name() == "name" {
			queryParam = p
			break
		}
	}
	if queryParam == nil {
		t.Fatal("Query parameter not found")
	}

	// + decoded to space in query
	if queryParam.Value() != "hello world" {
		t.Errorf("Query value = %q, want 'hello world'", queryParam.Value())
	}

	// Inject "foo bar" - space becomes +
	ip := NewParameterInsertionPoint(request, queryParam)
	result := ip.BuildRequest([]byte("foo bar"))
	expected := "GET /api?name=foo+bar HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(result) != expected {
		t.Errorf("BuildRequest mismatch:\ngot:  %q\nwant: %q", string(result), expected)
	}
}

// TestRoundTripEncoding verifies decode→encode round-trip produces valid requests.
func TestRoundTripEncoding(t *testing.T) {
	tests := []struct {
		name    string
		request string
	}{
		{
			name:    "query with encoded chars",
			request: "GET /api?q=hello%20world%26test%3D1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:    "path with encoded chars",
			request: "GET /api/hello%20world%2Ftest/data HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:    "cookie with encoded chars",
			request: "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc%3D123%26test\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			points, err := CreateAllInsertionPoints(request, false)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			for _, ip := range points {
				baseValue := ip.BaseValue()
				result := ip.BuildRequest([]byte(baseValue))

				if len(result) == 0 {
					t.Errorf("BuildRequest returned empty for %s", ip.Name())
					continue
				}

				// Re-analyze and verify value matches
				resultInfo, err := AnalyzeRequest(result)
				if err != nil {
					t.Errorf("Re-analyze failed for %s: %v", ip.Name(), err)
					continue
				}

				for _, p := range resultInfo.Parameters {
					if p.Name() == ip.Name() && p.Type().ToInsertionPointType() == ip.Type() {
						if p.Value() != baseValue {
							t.Errorf("Round-trip mismatch for %s: got %q, want %q",
								ip.Name(), p.Value(), baseValue)
						}
						break
					}
				}
			}
		})
	}
}

// TestCreateAllInsertionPointsEncoding tests CreateAllInsertionPoints decodes correctly.
func TestCreateAllInsertionPointsEncoding(t *testing.T) {
	request := []byte("GET /api/user%2Fadmin/data?filter=active%26archived&sort=name+asc HTTP/1.1\r\nHost: example.com\r\nCookie: token=abc%3D123\r\n\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	expected := map[string]struct {
		value  string
		ipType InsertionPointType
	}{
		"user/admin": {value: "user/admin", ipType: INS_URL_PATH_FOLDER},
		"filter":     {value: "active&archived", ipType: INS_PARAM_URL},
		"sort":       {value: "name asc", ipType: INS_PARAM_URL},
		"token":      {value: "abc=123", ipType: INS_PARAM_COOKIE},
	}

	for _, ip := range points {
		if exp, ok := expected[ip.Name()]; ok {
			if ip.BaseValue() != exp.value {
				t.Errorf("IP %q: BaseValue = %q, want %q", ip.Name(), ip.BaseValue(), exp.value)
			}
			if ip.Type() != exp.ipType {
				t.Errorf("IP %q: Type = %v, want %v", ip.Name(), ip.Type(), exp.ipType)
			}
			delete(expected, ip.Name())
		} else if ip.BaseValue() == "user/admin" {
			if ip.Type() != INS_URL_PATH_FOLDER {
				t.Errorf("Path param: Type = %v, want %v", ip.Type(), INS_URL_PATH_FOLDER)
			}
			delete(expected, "user/admin")
		}
	}
}
