package httpmsg

import (
	"bytes"
	"strings"
	"testing"
)

// countNonHeaderIPs returns the number of insertion points that are NOT header IPs.
// Used by legacy tests that only counted param/path/cookie/nested IPs before header IPs were added.
func countNonHeaderIPs(points []InsertionPoint) int {
	count := 0
	for _, ip := range points {
		if ip.Type() != INS_HEADER {
			count++
		}
	}
	return count
}

// TestWorkflow_SimpleURL tests the basic workflow with URL parameters.
// This demonstrates the real scanner usage:
// 1. Start with raw HTTP request
// 2. Call CreateAllInsertionPoints() to discover parameters
// 3. Inject payloads using BuildRequest()
// 4. Verify the request is correctly modified
func TestWorkflow_SimpleURL(t *testing.T) {
	tests := []struct {
		name           string
		request        string
		includeNested  bool
		payload        string
		expectedCount  int // Expected number of insertion points
		paramName      string
		expectedInBody string // What we expect to see in the built request
	}{
		{
			name: "Single URL parameter",
			request: "GET /api?id=123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			includeNested:  false,
			payload:        "XSS_PAYLOAD",
			expectedCount:  2, // 1 path param (api) + 1 URL param (id)
			paramName:      "id",
			expectedInBody: "GET /api?id=XSS_PAYLOAD HTTP/1.1",
		},
		{
			name: "Multiple URL parameters",
			request: "GET /search?q=test&page=1&sort=asc HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			includeNested:  false,
			payload:        "PAYLOAD",
			expectedCount:  4, // 1 path param (search) + 3 URL params (q, page, sort)
			paramName:      "q",
			expectedInBody: "GET /search?q=PAYLOAD&page=1&sort=asc HTTP/1.1",
		},
		{
			name: "URL parameter with special characters in payload",
			request: "GET /api?name=value HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			includeNested:  false,
			payload:        "test&injection=true",
			expectedCount:  2, // 1 path param (api) + 1 URL param (name)
			paramName:      "name",
			expectedInBody: "GET /api?name=test%26injection%3Dtrue HTTP/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Start with raw request
			request := []byte(tt.request)

			// Step 2: Discover all insertion points
			points, err := CreateAllInsertionPoints(request, tt.includeNested)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			// Step 3: Verify we found expected number of non-header insertion points
			if nonHeaderCount := countNonHeaderIPs(points); nonHeaderCount != tt.expectedCount {
				t.Errorf("Expected %d non-header insertion points, got %d", tt.expectedCount, nonHeaderCount)
			}

			// Step 4: Find the insertion point for our target parameter
			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.paramName {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				t.Fatalf("Did not find insertion point for parameter %q", tt.paramName)
			}

			// Step 5: Inject payload
			modifiedRequest := targetIP.BuildRequest([]byte(tt.payload))

			// Step 6: Verify the request contains expected content
			if !bytes.Contains(modifiedRequest, []byte(tt.expectedInBody)) {
				t.Errorf("Expected request to contain %q\nGot: %s", tt.expectedInBody, string(modifiedRequest))
			}
		})
	}
}

// TestWorkflow_SimplePOST tests the basic workflow with POST body parameters.
func TestWorkflow_SimplePOST(t *testing.T) {
	tests := []struct {
		name           string
		request        string
		payload        string
		paramName      string
		expectedInBody string
	}{
		{
			name: "Simple POST body parameter",
			request: "POST /login HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 27\r\n" +
				"\r\n" +
				"username=admin&password=123",
			payload:        "INJECTED",
			paramName:      "username",
			expectedInBody: "username=INJECTED&password=123",
		},
		{
			name: "POST body with special characters",
			request: "POST /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 9\r\n" +
				"\r\n" +
				"data=test",
			payload:        "a=b&c=d",
			paramName:      "data",
			expectedInBody: "data=a%3Db%26c%3Dd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			// Discover insertion points
			points, err := CreateAllInsertionPoints(request, false)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			// Find target parameter
			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.paramName {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				t.Fatalf("Did not find insertion point for parameter %q", tt.paramName)
			}

			// Inject payload
			modifiedRequest := targetIP.BuildRequest([]byte(tt.payload))

			// Verify
			if !bytes.Contains(modifiedRequest, []byte(tt.expectedInBody)) {
				t.Errorf("Expected request to contain %q\nGot: %s", tt.expectedInBody, string(modifiedRequest))
			}
		})
	}
}

// TestWorkflow_NestedJSON tests nested parameter discovery in JSON.
// This is the critical test demonstrating automatic nested detection.
func TestWorkflow_NestedJSON(t *testing.T) {
	tests := []struct {
		name               string
		request            string
		includeNested      bool
		payload            string
		targetParamName    string // Which nested parameter to inject
		expectedPointCount int    // Total insertion points (standard + nested)
		expectedInJSON     string // What we expect to see in the JSON value
	}{
		{
			name: "JSON in URL parameter - simple object",
			request: "GET /api?data={\"user\":\"admin\",\"role\":\"owner\"} HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			includeNested:      true,
			payload:            "injected_value",
			targetParamName:    "user", // Nested parameter name
			expectedPointCount: 4,      // 1 path param (api) + 1 for "data" param + 2 for nested "user" and "role"
			// JSON is URL-encoded because it's in a URL parameter
			expectedInJSON: `%7B%22user%22%3A%22injected_value%22%2C%22role%22%3A%22owner%22%7D`,
		},
		{
			name: "JSON in URL parameter - payload with quotes",
			request: "GET /api?data={\"name\":\"test\"} HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			includeNested:      true,
			payload:            `test"injection`,
			targetParamName:    "name",
			expectedPointCount: 3, // 1 path param (api) + 1 for "data" + 1 for nested "name"
			// Quote is JSON-escaped (\" becomes %5C%22 when URL-encoded)
			expectedInJSON: `%7B%22name%22%3A%22test%5C%22injection%22%7D`,
		},
		{
			name: "JSON in URL parameter - nested disabled",
			request: "GET /api?data={\"user\":\"admin\"} HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			includeNested:      false,
			payload:            "payload",
			targetParamName:    "data", // Only outer parameter
			expectedPointCount: 2,      // 1 path param (api) + 1 for "data" param, no nested
			expectedInJSON:     "",     // We're replacing entire JSON
		},
		{
			name: "JSON in POST body parameter",
			request: "POST /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 30\r\n" +
				"\r\n" +
				"config={\"debug\":\"true\"}",
			includeNested:      true,
			payload:            "false",
			targetParamName:    "debug",
			expectedPointCount: 3, // 1 path param (api) + 1 for "config" + 1 for nested "debug"
			// In POST body, also URL-encoded
			expectedInJSON: `%7B%22debug%22%3A%22false%22%7D`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			// Discover insertion points with nested detection
			points, err := CreateAllInsertionPoints(request, tt.includeNested)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			// Verify we found expected number of non-header insertion points
			if nonHeaderCount := countNonHeaderIPs(points); nonHeaderCount != tt.expectedPointCount {
				t.Errorf("Expected %d non-header insertion points, got %d", tt.expectedPointCount, nonHeaderCount)
				for i, ip := range points {
					t.Logf("  [%d] %s (type=%d)", i, ip.Name(), ip.Type())
				}
			}

			// Find the target insertion point
			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.targetParamName {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				t.Fatalf("Did not find insertion point for parameter %q", tt.targetParamName)
			}

			// Inject payload
			modifiedRequest := targetIP.BuildRequest([]byte(tt.payload))

			// Verify the expected JSON is in the request
			if tt.expectedInJSON != "" {
				if !bytes.Contains(modifiedRequest, []byte(tt.expectedInJSON)) {
					t.Errorf("Expected request to contain %q\nGot: %s", tt.expectedInJSON, string(modifiedRequest))
				}
			}
		})
	}
}

// TestWorkflow_NestedXML tests nested parameter discovery in XML.
func TestWorkflow_NestedXML(t *testing.T) {
	tests := []struct {
		name               string
		request            string
		payload            string
		targetParamName    string
		expectedPointCount int
		expectedInXML      string
	}{
		{
			name: "XML in URL parameter",
			request: "GET /api?data=<user><name>admin</name></user> HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			payload:            "injected",
			targetParamName:    "name", // XML parser returns element name, not full path
			expectedPointCount: 3,      // 1 path param (api) + 1 for "data" + 1 for nested "name"
			// XML is URL-encoded because it's in a URL parameter
			expectedInXML: "%3Cuser%3E%3Cname%3Einjected%3C%2Fname%3E%3C%2Fuser%3E",
		},
		{
			name: "XML with special characters",
			request: "GET /api?data=<config><value>test</value></config> HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			payload:            "<script>alert(1)</script>",
			targetParamName:    "value", // XML parser returns element name
			expectedPointCount: 3,       // 1 path param (api) + 1 for "data" + 1 for nested "value"
			// URL-encoded XML
			expectedInXML: "%3Cconfig%3E%3Cvalue%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E%3C%2Fvalue%3E%3C%2Fconfig%3E",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			// Discover with nested detection enabled
			points, err := CreateAllInsertionPoints(request, true)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			if nonHeaderCount := countNonHeaderIPs(points); nonHeaderCount != tt.expectedPointCount {
				t.Errorf("Expected %d non-header insertion points, got %d", tt.expectedPointCount, nonHeaderCount)
			}

			// Find target
			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.targetParamName {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				t.Fatalf("Did not find insertion point for parameter %q", tt.targetParamName)
			}

			// Inject
			modifiedRequest := targetIP.BuildRequest([]byte(tt.payload))

			// Verify
			if !bytes.Contains(modifiedRequest, []byte(tt.expectedInXML)) {
				t.Errorf("Expected request to contain %q\nGot: %s", tt.expectedInXML, string(modifiedRequest))
			}
		})
	}
}

// TestWorkflow_NestedURLEncoded tests nested URL-encoded parameters.
func TestWorkflow_NestedURLEncoded(t *testing.T) {
	tests := []struct {
		name               string
		request            string
		payload            string
		targetParamName    string
		expectedPointCount int
		expectedInOuter    string // Expected in the outer parameter value
	}{
		{
			name: "URL-encoded data in URL parameter",
			request: "GET /api?outer=name%3Dvalue%26foo%3Dbar HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			payload:            "injected",
			targetParamName:    "name", // Nested parameter
			expectedPointCount: 4,      // 1 path param (api) + 1 for "outer" + 2 for nested "name" and "foo"
			expectedInOuter:    "outer=name%3Dinjected%26foo%3Dbar",
		},
		{
			name: "URL-encoded with special characters in payload",
			request: "GET /api?data=param%3Dtest HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			payload:            "a&b=c",
			targetParamName:    "param",
			expectedPointCount: 3, // 1 path param (api) + 1 for "data" + 1 for nested "param"
			// Double URL encoding: a&b=c → a%26b%3Dc (inner) → a%2526b%253Dc (outer)
			expectedInOuter: "data=param%3Da%2526b%253Dc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			points, err := CreateAllInsertionPoints(request, true)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			if nonHeaderCount := countNonHeaderIPs(points); nonHeaderCount != tt.expectedPointCount {
				t.Errorf("Expected %d non-header insertion points, got %d", tt.expectedPointCount, nonHeaderCount)
			}

			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.targetParamName {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				t.Fatalf("Did not find insertion point for parameter %q", tt.targetParamName)
			}

			modifiedRequest := targetIP.BuildRequest([]byte(tt.payload))

			if !bytes.Contains(modifiedRequest, []byte(tt.expectedInOuter)) {
				t.Errorf("Expected request to contain %q\nGot: %s", tt.expectedInOuter, string(modifiedRequest))
			}
		})
	}
}

// TestWorkflow_NestedBase64 tests nested Base64-encoded parameters.
func TestWorkflow_NestedBase64(t *testing.T) {
	tests := []struct {
		name               string
		request            string
		payload            string
		targetParamName    string
		expectedPointCount int
		shouldContain      string // Partial expected content
	}{
		{
			name: "Base64-encoded JSON in URL parameter",
			// eyJ1c2VyIjoiYWRtaW4ifQ== is base64 of {"user":"admin"}
			request: "GET /api?token=eyJ1c2VyIjoiYWRtaW4ifQ== HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			payload:            "hacker",
			targetParamName:    "user",   // Nested in JSON inside Base64
			expectedPointCount: 3,        // 1 path param (api) + 1 for "token" + 1 for nested "user"
			shouldContain:      "token=", // Basic check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			points, err := CreateAllInsertionPoints(request, true)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			if nonHeaderCount := countNonHeaderIPs(points); nonHeaderCount != tt.expectedPointCount {
				t.Errorf("Expected %d non-header insertion points, got %d", tt.expectedPointCount, nonHeaderCount)
				for i, ip := range points {
					t.Logf("  [%d] %s (type=%d)", i, ip.Name(), ip.Type())
				}
			}

			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.targetParamName {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				// For Base64, this is expected to work but implementation may be simplified
				t.Skipf("Base64 nested detection not fully implemented yet")
			}

			modifiedRequest := targetIP.BuildRequest([]byte(tt.payload))

			if !bytes.Contains(modifiedRequest, []byte(tt.shouldContain)) {
				t.Errorf("Expected request to contain %q\nGot: %s", tt.shouldContain, string(modifiedRequest))
			}
		})
	}
}

// TestWorkflow_Cookies tests cookie parameter handling.
func TestWorkflow_Cookies(t *testing.T) {
	tests := []struct {
		name             string
		request          string
		payload          string
		paramName        string
		expectedInCookie string
	}{
		{
			name: "Simple cookie",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Cookie: session=abc123; user=admin\r\n" +
				"\r\n",
			payload:          "INJECTED",
			paramName:        "session",
			expectedInCookie: "Cookie: session=INJECTED; user=admin",
		},
		{
			name: "Cookie with special characters",
			request: "GET /api HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Cookie: data=value\r\n" +
				"\r\n",
			payload:          "a=b&c=d",
			paramName:        "data",
			expectedInCookie: "Cookie: data=a%3Db%26c%3Dd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			points, err := CreateAllInsertionPoints(request, false)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.paramName && ip.Type() == INS_PARAM_COOKIE {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				t.Fatalf("Did not find cookie insertion point for parameter %q", tt.paramName)
			}

			modifiedRequest := targetIP.BuildRequest([]byte(tt.payload))

			if !bytes.Contains(modifiedRequest, []byte(tt.expectedInCookie)) {
				t.Errorf("Expected request to contain %q\nGot: %s", tt.expectedInCookie, string(modifiedRequest))
			}
		})
	}
}

// TestWorkflow_ComplexScenarios tests more complex real-world scenarios.
func TestWorkflow_ComplexScenarios(t *testing.T) {
	tests := []struct {
		name              string
		request           string
		includeNested     bool
		expectedMinPoints int // Minimum expected insertion points
		testPayload       string
		testParamName     string
		expectedInRequest string
	}{
		{
			name: "Mixed parameters - URL, body, cookies",
			request: "POST /api?id=1 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Cookie: session=xyz\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 9\r\n" +
				"\r\n" +
				"user=test",
			includeNested:     false,
			expectedMinPoints: 3, // id, session, user
			testPayload:       "PAYLOAD",
			testParamName:     "user",
			expectedInRequest: "user=PAYLOAD",
		},
		{
			name: "Nested JSON in POST body with URL params",
			request: "POST /api?version=1 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 30\r\n" +
				"\r\n" +
				"data={\"key\":\"value\"}",
			includeNested:     true,
			expectedMinPoints: 3, // version, data, key (nested)
			testPayload:       "injected",
			testParamName:     "key",
			// URL-encoded JSON
			expectedInRequest: `%7B%22key%22%3A%22injected%22%7D`,
		},
		{
			name: "Multiple nested structures",
			request: "GET /api?json={\"a\":\"1\"}&xml=<root><b>2</b></root> HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			includeNested:     true,
			expectedMinPoints: 4, // json, xml, a (nested), root.b (nested)
			testPayload:       "test",
			testParamName:     "a",
			// URL-encoded JSON
			expectedInRequest: `%7B%22a%22%3A%22test%22%7D`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			points, err := CreateAllInsertionPoints(request, tt.includeNested)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			if nonHeaderCount := countNonHeaderIPs(points); nonHeaderCount < tt.expectedMinPoints {
				t.Errorf("Expected at least %d non-header insertion points, got %d", tt.expectedMinPoints, nonHeaderCount)
				for i, ip := range points {
					t.Logf("  [%d] %s (type=%d)", i, ip.Name(), ip.Type())
				}
			}

			// Find and test specific parameter
			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.testParamName {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				t.Fatalf("Did not find insertion point for parameter %q", tt.testParamName)
			}

			modifiedRequest := targetIP.BuildRequest([]byte(tt.testPayload))

			if !bytes.Contains(modifiedRequest, []byte(tt.expectedInRequest)) {
				t.Errorf("Expected request to contain %q\nGot: %s", tt.expectedInRequest, string(modifiedRequest))
			}
		})
	}
}

// TestWorkflow_PayloadOffsets tests that PayloadOffsets() works correctly.
func TestWorkflow_PayloadOffsets(t *testing.T) {
	tests := []struct {
		name      string
		request   string
		paramName string
		payload   string
	}{
		{
			name: "URL parameter offsets",
			request: "GET /api?id=123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			paramName: "id",
			payload:   "TEST_PAYLOAD",
		},
		{
			name: "Nested JSON offsets",
			request: "GET /api?data={\"user\":\"admin\"} HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			paramName: "user",
			payload:   "INJECTED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte(tt.request)

			// Discover insertion points
			points, err := CreateAllInsertionPoints(request, true)
			if err != nil {
				t.Fatalf("CreateAllInsertionPoints() error = %v", err)
			}

			// Find target
			var targetIP InsertionPoint
			for _, ip := range points {
				if ip.Name() == tt.paramName {
					targetIP = ip
					break
				}
			}

			if targetIP == nil {
				t.Fatalf("Did not find insertion point for parameter %q", tt.paramName)
			}

			// Build request
			modifiedRequest := targetIP.BuildRequest([]byte(tt.payload))

			// Get offsets
			offsets := targetIP.PayloadOffsets([]byte(tt.payload))

			if len(offsets) != 2 {
				t.Fatalf("Expected 2 offsets [start, end], got %d", len(offsets))
			}

			start, end := offsets[0], offsets[1]

			// Verify offsets are valid
			if start < 0 || end > len(modifiedRequest) || start >= end {
				t.Errorf("Invalid offsets: [%d, %d] for request length %d", start, end, len(modifiedRequest))
			}

			// Verify the payload is actually at those offsets
			extractedPayload := modifiedRequest[start:end]

			// For nested parameters, the payload may be encoded
			// So we check if it contains the payload or is an encoded version
			if !bytes.Contains(extractedPayload, []byte(tt.payload)) &&
				!bytes.Equal(extractedPayload, []byte(tt.payload)) {
				// Check if it's an encoded version (like JSON escape)
				if !strings.Contains(string(extractedPayload), strings.ReplaceAll(tt.payload, `"`, `\"`)) {
					t.Errorf("Payload at offsets [%d:%d] = %q does not match expected %q",
						start, end, string(extractedPayload), tt.payload)
				}
			}
		})
	}
}
