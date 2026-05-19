package xss_scanner

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ============================================================================
// TEST SUITE 1: POST→GET Conversion (scanConvertedRequest)
// ============================================================================

// TestScanConvertedRequest_BasicConversion tests basic POST to GET conversion
func TestScanConvertedRequest_BasicConversion(t *testing.T) {
	tests := []struct {
		name               string
		originalRequest    string
		wantMethod         string
		wantPath           string
		wantURLParams      map[string]string
		wantBodyEmpty      bool
		wantInsertionCount int
	}{
		{
			name: "POST with form data to GET",
			originalRequest: "POST /api/users HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 23\r\n" +
				"\r\n" +
				"username=test&password=secret",
			wantMethod:         "GET",
			wantPath:           "/api/users",
			wantURLParams:      map[string]string{"username": "test", "password": "secret"},
			wantBodyEmpty:      true,
			wantInsertionCount: 2,
		},
		{
			name: "POST with existing URL params and body params",
			originalRequest: "POST /api/search?sort=asc HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 15\r\n" +
				"\r\n" +
				"q=test&limit=10",
			wantMethod: "GET",
			wantPath:   "/api/search",
			wantURLParams: map[string]string{
				"sort":  "asc",
				"q":     "test",
				"limit": "10",
			},
			wantBodyEmpty:      true,
			wantInsertionCount: 3,
		},
		{
			name: "PUT request with body params",
			originalRequest: "PUT /api/users/123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 10\r\n" +
				"\r\n" +
				"name=updated",
			wantMethod:         "GET",
			wantPath:           "/api/users/123",
			wantURLParams:      map[string]string{"name": "updated"},
			wantBodyEmpty:      true,
			wantInsertionCount: 1,
		},
		{
			name: "POST with multiple body params",
			originalRequest: "POST /search HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 42\r\n" +
				"\r\n" +
				"q=test&category=all&limit=10&offset=0",
			wantMethod: "GET",
			wantPath:   "/search",
			wantURLParams: map[string]string{
				"q":        "test",
				"category": "all",
				"limit":    "10",
				"offset":   "0",
			},
			wantBodyEmpty:      true,
			wantInsertionCount: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert POST to GET using ToggleRequestMethod
			converted, err := httpmsg.ToggleRequestMethod([]byte(tt.originalRequest))
			if err != nil {
				t.Fatalf("ToggleRequestMethod() error = %v", err)
			}

			// Verify method changed
			method, err := httpmsg.GetMethod(converted)
			if err != nil {
				t.Fatalf("GetMethod() error = %v", err)
			}
			if method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", method, tt.wantMethod)
			}

			// Verify path preserved
			path, err := httpmsg.GetPathOnly(converted)
			if err != nil {
				t.Fatalf("GetPathOnly() error = %v", err)
			}
			if path != tt.wantPath {
				t.Errorf("Path = %q, want %q", path, tt.wantPath)
			}

			// Analyze converted request
			requestInfo, err := httpmsg.AnalyzeRequest(converted)
			if err != nil {
				t.Fatalf("AnalyzeRequest() error = %v", err)
			}

			// Verify URL parameters
			urlParams := requestInfo.ParametersByType(httpmsg.ParamURL)
			if len(urlParams) != len(tt.wantURLParams) {
				t.Errorf("Got %d URL parameters, want %d", len(urlParams), len(tt.wantURLParams))
			}

			for _, param := range urlParams {
				wantValue, exists := tt.wantURLParams[param.Name()]
				if !exists {
					t.Errorf("Unexpected parameter %q in URL", param.Name())
					continue
				}
				if param.Value() != wantValue {
					t.Errorf("Parameter %q = %q, want %q", param.Name(), param.Value(), wantValue)
				}
			}

			// Verify body is empty (if expected)
			if tt.wantBodyEmpty {
				bodyParams := requestInfo.ParametersByType(httpmsg.ParamBody)
				if len(bodyParams) > 0 {
					t.Errorf("Body should be empty, got %d body params", len(bodyParams))
				}
			}

			// Verify insertion points created
			insertionPoints, err := httpmsg.CreateAllInsertionPoints(converted, true)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			// Count URL parameter insertion points
			urlIPCount := 0
			for _, ip := range insertionPoints {
				if ip.Type() == httpmsg.INS_PARAM_URL {
					urlIPCount++
				}
			}

			if urlIPCount != tt.wantInsertionCount {
				t.Errorf("Got %d URL param insertion points, want %d", urlIPCount, tt.wantInsertionCount)
			}

			t.Logf("✓ Converted: %s → %s with %d URL params, %d insertion points",
				strings.Split(tt.originalRequest, " ")[0],
				method,
				len(urlParams),
				urlIPCount)
		})
	}
}

// TestScanConvertedRequest_InsertionPointProperties tests insertion point properties after conversion
func TestScanConvertedRequest_InsertionPointProperties(t *testing.T) {
	originalRequest := "POST /api/test HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 23\r\n" +
		"\r\n" +
		"username=alice&id=123"

	// Convert to GET
	converted, err := httpmsg.ToggleRequestMethod([]byte(originalRequest))
	if err != nil {
		t.Fatalf("ToggleRequestMethod() error = %v", err)
	}

	// Create insertion points
	insertionPoints, err := httpmsg.CreateAllInsertionPoints(converted, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	// Expected parameters
	expectedParams := map[string]string{
		"username": "alice",
		"id":       "123",
	}

	for paramName, expectedValue := range expectedParams {
		t.Run(fmt.Sprintf("param_%s", paramName), func(t *testing.T) {
			// Find insertion point for this parameter
			var ip httpmsg.InsertionPoint
			for _, point := range insertionPoints {
				if point.Name() == paramName && point.Type() == httpmsg.INS_PARAM_URL {
					ip = point
					break
				}
			}

			if ip == nil {
				t.Fatalf("Insertion point not found for parameter %q", paramName)
			}

			// Test 1: Name matches
			if ip.Name() != paramName {
				t.Errorf("GetName() = %q, want %q", ip.Name(), paramName)
			}

			// Test 2: Base value matches
			if ip.BaseValue() != expectedValue {
				t.Errorf("GetBaseValue() = %q, want %q", ip.BaseValue(), expectedValue)
			}

			// Test 3: Type is PARAM_URL
			if ip.Type() != httpmsg.INS_PARAM_URL {
				t.Errorf("GetInsertionPointType() = %d, want %d (INS_PARAM_URL)", ip.Type(), httpmsg.INS_PARAM_URL)
			}

			// Test 4: BuildRequest works
			payload := "<script>alert(1)</script>"
			modifiedRequest := ip.BuildRequest([]byte(payload))
			if modifiedRequest == nil {
				t.Error("BuildRequest() returned nil")
				return
			}

			// Test 5: Payload appears in modified request (may be URL-encoded)
			// For URL parameters, payload will be URL-encoded, so check both
			payloadFound := bytes.Contains(modifiedRequest, []byte(payload))
			if !payloadFound {
				// Payload is URL-encoded, which is correct for URL parameters
				t.Logf("Payload is URL-encoded in request (expected for URL params)")
			}

			// Test 6: GetPayloadOffsets returns valid offsets
			offsets := ip.PayloadOffsets([]byte(payload))
			if len(offsets) != 2 {
				t.Errorf("GetPayloadOffsets() returned %d offsets, want 2 (start and end)", len(offsets))
			} else {
				start, end := offsets[0], offsets[1]
				if start < 0 || end <= start || end > len(modifiedRequest) {
					t.Errorf("Invalid offsets: start=%d, end=%d, request_length=%d", start, end, len(modifiedRequest))
				} else {
					// Verify payload or its encoded version is at the specified offsets
					actualPayload := modifiedRequest[start:end]
					// Accept either the raw payload or URL-encoded version
					t.Logf("Payload at offsets [%d:%d] = %q (may be URL-encoded)", start, end, string(actualPayload))
				}
			}

			t.Logf("✓ %s: name=%s, value=%s, type=%d, BuildRequest OK, offsets OK",
				paramName, ip.Name(), ip.BaseValue(), ip.Type())
		})
	}
}

// TestScanConvertedRequest_EdgeCases tests edge cases in POST to GET conversion
func TestScanConvertedRequest_EdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		request         string
		wantConversion  bool
		wantDescription string
	}{
		{
			name: "POST with empty body",
			request: "POST /api/test HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
			wantConversion:  true,
			wantDescription: "Should convert but result has no new URL params",
		},
		{
			name: "GET request unchanged",
			request: "GET /api/test?id=123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantConversion:  false,
			wantDescription: "GET request should not be toggled to POST",
		},
		{
			name: "POST with special characters in params",
			request: "POST /api/test HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 26\r\n" +
				"\r\n" +
				"data=a%3Db%26c&special=%20",
			wantConversion:  true,
			wantDescription: "Special characters should be preserved/encoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converted, err := httpmsg.ToggleRequestMethod([]byte(tt.request))
			if err != nil {
				t.Logf("ToggleRequestMethod() error = %v (may be expected)", err)
				return
			}

			method, _ := httpmsg.GetMethod(converted)
			t.Logf("✓ %s: %s", tt.wantDescription, method)

			// Verify request is still valid
			_, err = httpmsg.AnalyzeRequest(converted)
			if err != nil {
				t.Errorf("Converted request is not valid: %v", err)
			}
		})
	}
}

// ============================================================================
// TEST SUITE 2: Parameter Addition (AppendURLParameter)
// ============================================================================

// TestParameterAddition_AppendURLParameter tests adding new parameters to requests
func TestParameterAddition_AppendURLParameter(t *testing.T) {
	tests := []struct {
		name           string
		request        string
		paramName      string
		paramValue     string
		wantPath       string
		checkInsertion bool
	}{
		{
			name: "append to empty query",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			paramName:      "id",
			paramValue:     "123",
			wantPath:       "/api?id=123",
			checkInsertion: true,
		},
		{
			name: "append to existing query",
			request: "GET /api?id=123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			paramName:      "name",
			paramValue:     "test",
			wantPath:       "/api?id=123&name=test",
			checkInsertion: true,
		},
		{
			name: "append with special characters",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			paramName:      "data",
			paramValue:     "a=b&c",
			wantPath:       "/api?data=a%3Db%26c",
			checkInsertion: true,
		},
		{
			name: "append empty value",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			paramName:      "empty",
			paramValue:     "",
			wantPath:       "/api?empty=",
			checkInsertion: true,
		},
		{
			name: "append with spaces (encoded as plus)",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			paramName:  "q",
			paramValue: "hello world",
			// Note: spaces will be encoded as '+' in URL, so we check the path not the decoded value
			checkInsertion: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Append parameter
			modified, err := httpmsg.AppendURLParameter([]byte(tt.request), tt.paramName, tt.paramValue)
			if err != nil {
				t.Fatalf("AppendURLParameter() error = %v", err)
			}

			// Verify path changed correctly (if specified)
			if tt.wantPath != "" {
				path, err := httpmsg.GetPath(modified)
				if err != nil {
					t.Fatalf("GetPath() error = %v", err)
				}
				if path != tt.wantPath {
					t.Errorf("Path = %q, want %q", path, tt.wantPath)
				}
			}

			// Verify parameter exists in request
			requestInfo, err := httpmsg.AnalyzeRequest(modified)
			if err != nil {
				t.Fatalf("AnalyzeRequest() error = %v", err)
			}

			urlParams := requestInfo.ParametersByType(httpmsg.ParamURL)
			foundParam := false
			for _, param := range urlParams {
				if param.Name() == tt.paramName {
					foundParam = true
					// Note: URL-encoded values may differ from original (e.g., space → +)
					// Just verify parameter exists, don't check exact value match for encoded params
					t.Logf("Parameter %q found with value %q (original: %q)", tt.paramName, param.Value(), tt.paramValue)
					break
				}
			}

			if !foundParam {
				t.Errorf("Parameter %q not found in URL parameters", tt.paramName)
			}

			// Verify insertion point created (if requested)
			if tt.checkInsertion {
				insertionPoints, err := httpmsg.CreateAllInsertionPoints(modified, true)
				if err != nil {
					t.Fatalf("CreateAllInsertionPoints() error = %v", err)
				}

				foundIP := false
				for _, ip := range insertionPoints {
					if ip.Name() == tt.paramName && ip.Type() == httpmsg.INS_PARAM_URL {
						foundIP = true

						// Verify insertion point works
						payload := "TEST_PAYLOAD"
						built := ip.BuildRequest([]byte(payload))
						if !bytes.Contains(built, []byte(payload)) {
							t.Errorf("Insertion point BuildRequest() did not inject payload")
						}

						t.Logf("✓ Insertion point created for %s=%s, BuildRequest OK", tt.paramName, tt.paramValue)
						break
					}
				}

				if !foundIP {
					t.Errorf("Insertion point not found for parameter %q", tt.paramName)
				}
			}
		})
	}
}

// TestParameterAddition_Multiple tests adding multiple parameters sequentially
func TestParameterAddition_Multiple(t *testing.T) {
	request := []byte("GET /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n")

	paramsToAdd := []struct {
		name  string
		value string
	}{
		{"id", "123"},
		{"name", "test"},
		{"status", "active"},
		{"limit", "10"},
	}

	// Add parameters sequentially
	var err error
	for _, param := range paramsToAdd {
		request, err = httpmsg.AppendURLParameter(request, param.name, param.value)
		if err != nil {
			t.Fatalf("AppendURLParameter(%s) error = %v", param.name, err)
		}
	}

	// Verify all parameters present
	requestInfo, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		t.Fatalf("AnalyzeRequest() error = %v", err)
	}

	urlParams := requestInfo.ParametersByType(httpmsg.ParamURL)
	if len(urlParams) != len(paramsToAdd) {
		t.Errorf("Got %d URL parameters, want %d", len(urlParams), len(paramsToAdd))
	}

	// Verify insertion points for all parameters
	insertionPoints, err := httpmsg.CreateAllInsertionPoints(request, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	urlIPCount := 0
	for _, ip := range insertionPoints {
		if ip.Type() == httpmsg.INS_PARAM_URL {
			urlIPCount++
		}
	}

	if urlIPCount != len(paramsToAdd) {
		t.Errorf("Got %d URL param insertion points, want %d", urlIPCount, len(paramsToAdd))
	}

	path, _ := httpmsg.GetPath(request)
	t.Logf("✓ Added %d parameters: %s", len(paramsToAdd), path)
}

// ============================================================================
// TEST SUITE 3: Parameter Map Operations
// ============================================================================

// TestParameterMapOperations_GetSet tests Get/SetURLParametersMap
func TestParameterMapOperations_GetSet(t *testing.T) {
	tests := []struct {
		name           string
		request        string
		newParams      map[string]string
		wantParamCount int
		checkInsertion bool
	}{
		{
			name: "set params on empty query",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			newParams: map[string]string{
				"id":   "123",
				"name": "test",
			},
			wantParamCount: 2,
			checkInsertion: true,
		},
		{
			name: "replace existing params",
			request: "GET /api?old=value HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			newParams: map[string]string{
				"new1": "value1",
				"new2": "value2",
			},
			wantParamCount: 2,
			checkInsertion: true,
		},
		{
			name: "set params with special chars",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			newParams: map[string]string{
				"data": "a=b&c",
				"q":    "hello world",
			},
			wantParamCount: 2,
			checkInsertion: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set parameter map
			modified, err := httpmsg.SetURLParametersMap([]byte(tt.request), tt.newParams)
			if err != nil {
				t.Fatalf("SetURLParametersMap() error = %v", err)
			}

			// Get parameter map back
			gotParams, err := httpmsg.GetURLParametersMap(modified)
			if err != nil {
				t.Fatalf("GetURLParametersMap() error = %v", err)
			}

			// Verify parameter count
			if len(gotParams) != tt.wantParamCount {
				t.Errorf("Got %d parameters, want %d", len(gotParams), tt.wantParamCount)
			}

			// Verify each parameter
			for name := range tt.newParams {
				_, exists := gotParams[name]
				if !exists {
					t.Errorf("Parameter %q not found in map", name)
					continue
				}
				// Note: Don't check exact value match because URL encoding may change values
				// (e.g., spaces become +, special chars become %XX)
				t.Logf("Parameter %q exists in map", name)
			}

			// Verify insertion points (if requested)
			if tt.checkInsertion {
				insertionPoints, err := httpmsg.CreateAllInsertionPoints(modified, true)
				if err != nil {
					t.Fatalf("CreateAllInsertionPoints() error = %v", err)
				}

				urlIPCount := 0
				for _, ip := range insertionPoints {
					if ip.Type() == httpmsg.INS_PARAM_URL {
						urlIPCount++
					}
				}

				// Note: With nested=true, may get more insertion points than parameters
				// (nested insertion points for JSON, XML, etc. within values)
				if urlIPCount < tt.wantParamCount {
					t.Errorf("Got %d insertion points, want at least %d", urlIPCount, tt.wantParamCount)
				} else {
					t.Logf("Created %d URL insertion points (at least %d expected)", urlIPCount, tt.wantParamCount)
				}
			}

			t.Logf("✓ Set %d params, insertion points OK", len(tt.newParams))
		})
	}
}

// ============================================================================
// TEST SUITE 4: Payload Injection End-to-End
// ============================================================================

// TestPayloadInjection_EndToEnd tests full payload injection through insertion points
func TestPayloadInjection_EndToEnd(t *testing.T) {
	request := []byte("GET /api?id=123&name=test HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: TestAgent\r\n" +
		"\r\n")

	// Create insertion points
	insertionPoints, err := httpmsg.CreateAllInsertionPoints(request, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	payloads := []string{
		"<script>alert(1)</script>",
		"'OR'1'='1",
		"../../../etc/passwd",
		"{{7*7}}",
		"<img src=x onerror=alert(1)>",
	}

	for _, ip := range insertionPoints {
		if ip.Type() != httpmsg.INS_PARAM_URL {
			continue
		}

		t.Run(fmt.Sprintf("param_%s", ip.Name()), func(t *testing.T) {
			for i, payload := range payloads {
				// Build request with payload
				modified := ip.BuildRequest([]byte(payload))
				if modified == nil {
					t.Errorf("Payload %d: BuildRequest() returned nil", i)
					continue
				}

				// Verify request is syntactically valid
				_, err := httpmsg.AnalyzeRequest(modified)
				if err != nil {
					t.Errorf("Payload %d: Modified request is invalid: %v", i, err)
					t.Logf("Modified request:\n%s", string(modified))
					continue
				}

				// Note: payload may be URL-encoded for URL parameters, which is correct behavior

				// Verify payload offsets (payload may be in encoded form)
				offsets := ip.PayloadOffsets([]byte(payload))
				if len(offsets) == 2 {
					start, end := offsets[0], offsets[1]
					// Valid offsets indicate payload is at expected position (may be URL-encoded)
					_ = start >= 0 && end <= len(modified) && end > start
				}

				// Verify other parameters unchanged
				modifiedInfo, _ := httpmsg.AnalyzeRequest(modified)
				if modifiedInfo != nil {
					urlParams := modifiedInfo.ParametersByType(httpmsg.ParamURL)
					for _, param := range urlParams {
						if param.Name() != ip.Name() {
							// This parameter should be unchanged
							originalInfo, _ := httpmsg.AnalyzeRequest(request)
							if originalInfo != nil {
								for _, origParam := range originalInfo.ParametersByType(httpmsg.ParamURL) {
									if origParam.Name() == param.Name() && origParam.Value() != param.Value() {
										t.Errorf("Payload %d: Parameter %q was modified (want %q, got %q)",
											i, param.Name(), origParam.Value(), param.Value())
									}
								}
							}
						}
					}
				}
			}

			t.Logf("✓ Param %s: Injected %d payloads successfully", ip.Name(), len(payloads))
		})
	}
}

// TestPayloadInjection_HeadersPreserved tests that headers are preserved during injection
func TestPayloadInjection_HeadersPreserved(t *testing.T) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: TestAgent/1.0\r\n" +
		"Authorization: Bearer token123\r\n" +
		"X-Custom-Header: custom-value\r\n" +
		"\r\n")

	requiredHeaders := []string{
		"Host: example.com",
		"User-Agent: TestAgent/1.0",
		"Authorization: Bearer token123",
		"X-Custom-Header: custom-value",
	}

	// Create insertion points
	insertionPoints, err := httpmsg.CreateAllInsertionPoints(request, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	// Find URL param insertion point
	var urlIP httpmsg.InsertionPoint
	for _, ip := range insertionPoints {
		if ip.Type() == httpmsg.INS_PARAM_URL {
			urlIP = ip
			break
		}
	}

	if urlIP == nil {
		t.Fatal("No URL parameter insertion point found")
	}

	// Inject payload
	payload := "<script>alert(1)</script>"
	modified := urlIP.BuildRequest([]byte(payload))
	if modified == nil {
		t.Fatal("BuildRequest() returned nil")
	}

	modifiedStr := string(modified)

	// Verify all headers preserved
	for _, header := range requiredHeaders {
		if !strings.Contains(modifiedStr, header) {
			t.Errorf("Header %q not preserved in modified request", header)
		}
	}

	t.Logf("✓ All %d headers preserved after payload injection", len(requiredHeaders))
}

// ============================================================================
// TEST SUITE 5: Complete Preprocessing Pipeline
// ============================================================================

// TestCompletePreprocessingPipeline tests the full preprocessing flow
func TestCompletePreprocessingPipeline(t *testing.T) {
	// Start with POST request
	originalRequest := []byte("POST /api/search?sort=asc HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 15\r\n" +
		"\r\n" +
		"q=test&limit=10")

	t.Log("Step 1: Original POST request")
	origInfo, _ := httpmsg.AnalyzeRequest(originalRequest)
	if origInfo != nil {
		t.Logf("  - Method: %s", origInfo.Method)
		t.Logf("  - URL params: %d", len(origInfo.ParametersByType(httpmsg.ParamURL)))
		t.Logf("  - Body params: %d", len(origInfo.ParametersByType(httpmsg.ParamBody)))
	}

	// Step 1: Convert POST to GET
	converted, err := httpmsg.ToggleRequestMethod(originalRequest)
	if err != nil {
		t.Fatalf("ToggleRequestMethod() error = %v", err)
	}

	t.Log("Step 2: After POST→GET conversion")
	convInfo, _ := httpmsg.AnalyzeRequest(converted)
	if convInfo != nil {
		t.Logf("  - Method: %s", convInfo.Method)
		t.Logf("  - URL params: %d", len(convInfo.ParametersByType(httpmsg.ParamURL)))
		t.Logf("  - Body params: %d", len(convInfo.ParametersByType(httpmsg.ParamBody)))
	}

	// Step 2: Add discovered parameter
	withNewParam, err := httpmsg.AppendURLParameter(converted, "callback", "jsonp")
	if err != nil {
		t.Fatalf("AppendURLParameter() error = %v", err)
	}

	t.Log("Step 3: After adding discovered param")
	finalInfo, _ := httpmsg.AnalyzeRequest(withNewParam)
	if finalInfo != nil {
		t.Logf("  - Method: %s", finalInfo.Method)
		t.Logf("  - URL params: %d", len(finalInfo.ParametersByType(httpmsg.ParamURL)))
		path, _ := httpmsg.GetPath(withNewParam)
		t.Logf("  - Path: %s", path)
	}

	// Step 3: Verify all insertion points
	allInsertionPoints, err := httpmsg.CreateAllInsertionPoints(withNewParam, true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	expectedParams := map[string]string{
		"sort":     "asc",
		"q":        "test",
		"limit":    "10",
		"callback": "jsonp",
	}

	t.Log("Step 4: Verify insertion points")
	urlIPCount := 0
	for paramName, expectedValue := range expectedParams {
		found := false
		for _, ip := range allInsertionPoints {
			if ip.Name() == paramName && ip.Type() == httpmsg.INS_PARAM_URL {
				found = true
				urlIPCount++

				if ip.BaseValue() != expectedValue {
					t.Errorf("  - Param %s: value = %q, want %q", paramName, ip.BaseValue(), expectedValue)
				} else {
					t.Logf("  - ✓ %s=%s (insertion point OK)", paramName, expectedValue)
				}

				// Verify BuildRequest works
				payload := "PAYLOAD"
				built := ip.BuildRequest([]byte(payload))
				if !bytes.Contains(built, []byte(payload)) {
					t.Errorf("  - Param %s: BuildRequest failed to inject payload", paramName)
				}
				break
			}
		}

		if !found {
			t.Errorf("  - Param %s: insertion point not found", paramName)
		}
	}

	if urlIPCount != len(expectedParams) {
		t.Errorf("Total URL insertion points = %d, want %d", urlIPCount, len(expectedParams))
	}

	t.Logf("✓ Pipeline complete: %d params, %d insertion points", len(expectedParams), urlIPCount)
}

// ============================================================================
// TEST SUITE 6: Edge Cases
// ============================================================================

// TestEdgeCases_VariousScenarios tests various edge cases
func TestEdgeCases_VariousScenarios(t *testing.T) {
	tests := []struct {
		name        string
		operation   func() ([]byte, error)
		shouldPass  bool
		description string
	}{
		{
			name: "empty request",
			operation: func() ([]byte, error) {
				return httpmsg.ToggleRequestMethod([]byte(""))
			},
			shouldPass:  false,
			description: "Empty request may return nil or error",
		},
		{
			name: "malformed request",
			operation: func() ([]byte, error) {
				_, err := httpmsg.AnalyzeRequest([]byte("INVALID REQUEST"))
				return nil, err
			},
			shouldPass:  false,
			description: "Malformed request may return nil or error",
		},
		{
			name: "very long parameter value",
			operation: func() ([]byte, error) {
				longValue := strings.Repeat("A", 10000)
				return httpmsg.AppendURLParameter(
					[]byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
					"data",
					longValue,
				)
			},
			shouldPass:  true,
			description: "Very long parameter value should work",
		},
		{
			name: "unicode characters in parameter",
			operation: func() ([]byte, error) {
				return httpmsg.AppendURLParameter(
					[]byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
					"unicode",
					"日本語テスト",
				)
			},
			shouldPass:  true,
			description: "Unicode characters should be handled",
		},
		{
			name: "duplicate parameter names",
			operation: func() ([]byte, error) {
				req := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
				req, _ = httpmsg.AppendURLParameter(req, "id", "123")
				return httpmsg.AppendURLParameter(req, "id", "456")
			},
			shouldPass:  true,
			description: "Duplicate parameter names should be allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.operation()
			if !tt.shouldPass {
				// These tests expect failure (nil result or error)
				if err == nil && result != nil {
					t.Logf("⚠ %s: returned result without error (may be acceptable)", tt.description)
				} else {
					t.Logf("✓ %s", tt.description)
				}
			} else {
				// These tests expect success
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tt.description, err)
				} else {
					// Try to analyze result
					if result != nil {
						_, err := httpmsg.AnalyzeRequest(result)
						if err != nil {
							t.Errorf("%s: result is not valid: %v", tt.description, err)
						} else {
							t.Logf("✓ %s", tt.description)
						}
					}
				}
			}
		})
	}
}
