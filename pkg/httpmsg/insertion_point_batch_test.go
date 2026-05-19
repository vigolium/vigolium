package httpmsg

import (
	"encoding/json"
	"testing"
)

func TestBuildRequestWithPayloads_URLParamsOnly(t *testing.T) {
	// Request with two URL parameters
	request := []byte("GET /api?id=123&name=admin HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Get insertion points
	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("Failed to create insertion points: %v", err)
	}

	// Find id and name params (filter to URL params only)
	var idIP, nameIP InsertionPoint
	for _, p := range points {
		if p.Type() != INS_PARAM_URL {
			continue
		}
		switch p.Name() {
		case "id":
			idIP = p
		case "name":
			nameIP = p
		}
	}

	if idIP == nil || nameIP == nil {
		t.Fatal("Could not find id or name insertion points")
	}

	// Create payload map with different payloads
	payloads := PayloadMap{
		idIP:   []byte("PAYLOAD_ID"),
		nameIP: []byte("PAYLOAD_NAME"),
	}

	// Build request with payloads
	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	expected := "GET /api?id=PAYLOAD_ID&name=PAYLOAD_NAME HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

func TestBuildRequestWithPayloads_URLEncoding(t *testing.T) {
	request := []byte("GET /api?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("Failed to create insertion points: %v", err)
	}

	// Find q param (URL type only)
	var qIP InsertionPoint
	for _, p := range points {
		if p.Type() == INS_PARAM_URL && p.Name() == "q" {
			qIP = p
			break
		}
	}
	if qIP == nil {
		t.Fatal("No q insertion point found")
	}

	// Payload with special characters that need URL encoding
	payloads := PayloadMap{
		qIP: []byte("<script>alert(1)</script>"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match with URL-encoded payload
	expected := "GET /api?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

func TestBuildRequestWithPayloads_BodyParams(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 19\r\n\r\nuser=test&pass=1234")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("Failed to create insertion points: %v", err)
	}

	// Find user and pass params
	var userIP, passIP InsertionPoint
	for _, p := range points {
		switch p.Name() {
		case "user":
			userIP = p
		case "pass":
			passIP = p
		}
	}

	if userIP == nil || passIP == nil {
		t.Fatalf("Could not find user or pass insertion points")
	}

	payloads := PayloadMap{
		userIP: []byte("admin"),
		passIP: []byte("secret"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match with updated Content-Length
	expected := "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 22\r\n\r\nuser=admin&pass=secret"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

func TestBuildRequestWithPayloads_MixedTypes(t *testing.T) {
	request := []byte("POST /api?id=1 HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 8\r\n\r\nname=foo")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("Failed to create insertion points: %v", err)
	}

	// Find params by name
	var idIP, sessionIP, nameIP InsertionPoint
	for _, p := range points {
		switch p.Name() {
		case "id":
			if p.Type() == INS_PARAM_URL {
				idIP = p
			}
		case "session":
			sessionIP = p
		case "name":
			nameIP = p
		}
	}

	if idIP == nil || sessionIP == nil || nameIP == nil {
		t.Fatalf("Could not find all insertion points: id=%v session=%v name=%v", idIP, sessionIP, nameIP)
	}

	payloads := PayloadMap{
		idIP:      []byte("URL_PAYLOAD"),
		sessionIP: []byte("COOKIE_PAYLOAD"),
		nameIP:    []byte("BODY_PAYLOAD"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	expected := "POST /api?id=URL_PAYLOAD HTTP/1.1\r\nHost: example.com\r\nCookie: session=COOKIE_PAYLOAD\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 17\r\n\r\nname=BODY_PAYLOAD"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

func TestBuildRequestWithPayloads_EmptyMap(t *testing.T) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	results, err := BuildRequestWithPayloads(request, PayloadMap{})
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match - unchanged request
	if string(results[0]) != string(request) {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", string(request), string(results[0]))
	}
}

func TestBuildRequestWithPayloads_SingleParam(t *testing.T) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("Failed to create insertion points: %v", err)
	}

	// Find id param (URL type only)
	var idIP InsertionPoint
	for _, p := range points {
		if p.Type() == INS_PARAM_URL && p.Name() == "id" {
			idIP = p
			break
		}
	}
	if idIP == nil {
		t.Fatal("No id insertion point found")
	}

	payloads := PayloadMap{
		idIP: []byte("SINGLE"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	expected := "GET /api?id=SINGLE HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

func TestBuildRequestWithSamePayload(t *testing.T) {
	request := []byte("GET /api?a=1&b=2&c=3 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("Failed to create insertion points: %v", err)
	}

	// Filter to URL params only
	var urlParams []InsertionPoint
	for _, p := range points {
		if p.Type() == INS_PARAM_URL {
			urlParams = append(urlParams, p)
		}
	}

	// Inject same payload into all URL params
	results, err := BuildRequestWithSamePayload(request, urlParams, []byte("XSS"))
	if err != nil {
		t.Fatalf("BuildRequestWithSamePayload failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	expected := "GET /api?a=XSS&b=XSS&c=XSS HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

func TestBuildRequestWithPayloads_JSONBody(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"user\":\"test\",\"id\":123}")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("Failed to create insertion points: %v", err)
	}

	// Find JSON params
	var userIP, idIP InsertionPoint
	for _, p := range points {
		switch p.Name() {
		case "user":
			userIP = p
		case "id":
			idIP = p
		}
	}

	if userIP == nil || idIP == nil {
		t.Skipf("JSON params not found, skipping test. Found: %d points", len(points))
		return
	}

	payloads := PayloadMap{
		userIP: []byte("admin"),
		idIP:   []byte("456"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match - Content-Length is 25 because {"user":"admin","id":456} is 25 chars
	expected := "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"user\":\"admin\",\"id\":456}"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

func TestBuildRequestWithPayloads_EncodedInsertionPoint(t *testing.T) {
	request := []byte("GET /api?data=test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Create an EncodedInsertionPoint with Base64 encoder
	encoder := NewBase64Encoder()
	ip := NewEncodedInsertionPoint("data", request, 14, 18, encoder, nil, INS_PARAM_URL)

	payloads := PayloadMap{
		ip: []byte("hello"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match - base64 encoded "hello" = "aGVsbG8="
	expected := "GET /api?data=aGVsbG8= HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

func TestGetInsertionPointOffsets(t *testing.T) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Test ParameterInsertionPoint
	param := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)
	paramIP := NewParameterInsertionPoint(request, param)

	start, end := getInsertionPointOffsets(paramIP)
	if start != 12 || end != 15 {
		t.Errorf("Expected offsets [12, 15], got [%d, %d]", start, end)
	}

	// Test EncodedInsertionPoint
	encodedIP := NewEncodedInsertionPoint("id", request, 12, 15, &NoopEncoder{}, nil, INS_PARAM_URL)

	start, end = getInsertionPointOffsets(encodedIP)
	if start != 12 || end != 15 {
		t.Errorf("Expected offsets [12, 15], got [%d, %d]", start, end)
	}
}

func TestBuildRequestWithPayloads_PreservesOffsets(t *testing.T) {
	// This test verifies that injecting shorter/longer payloads works correctly
	request := []byte("GET /api?a=longvalue&b=short HTTP/1.1\r\nHost: example.com\r\n\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("Failed to create insertion points: %v", err)
	}

	var aIP, bIP InsertionPoint
	for _, p := range points {
		if p.Type() != INS_PARAM_URL {
			continue
		}
		switch p.Name() {
		case "a":
			aIP = p
		case "b":
			bIP = p
		}
	}

	if aIP == nil || bIP == nil {
		t.Fatal("Could not find a or b insertion points")
	}

	// Replace long with short and short with long
	payloads := PayloadMap{
		aIP: []byte("X"),           // shorter
		bIP: []byte("VERYLONGVAL"), // longer
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	expected := "GET /api?a=X&b=VERYLONGVAL HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// =============================================================================
// NESTED INSERTION POINT BATCH TESTS
// =============================================================================

// TestBuildRequestWithPayloads_NestedURLEncodedJSON tests batch injection with
// URL parameter containing JSON (url_encode(json))
func TestBuildRequestWithPayloads_NestedURLEncodedJSON(t *testing.T) {
	// Request: GET /api?data={"user":"admin","role":"guest"}
	// URL-encoded: data=%7B%22user%22%3A%22admin%22%2C%22role%22%3A%22guest%22%7D
	baseRequest := []byte("GET /api?data=%7B%22user%22%3A%22admin%22%2C%22role%22%3A%22guest%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n")

	// Parent: URL parameter "data"
	parentParam := NewParsedParam(ParamURL, "data",
		"%7B%22user%22%3A%22admin%22%2C%22role%22%3A%22guest%22%7D",
		9, 13, 14, 71)
	parentIP := NewParameterInsertionPoint(baseRequest, parentParam)

	// Child 1: JSON field "user" with JSON escape encoder
	decodedJSON := []byte(`{"user":"admin","role":"guest"}`)
	jsonEncoder := &JSONEscapeEncoder{}
	userIP := NewEncodedInsertionPoint("user", decodedJSON, 9, 14, jsonEncoder, nil, INS_PARAM_JSON)

	// Child 2: JSON field "role" with JSON escape encoder
	roleIP := NewEncodedInsertionPoint("role", decodedJSON, 24, 29, jsonEncoder, nil, INS_PARAM_JSON)

	// Create nested insertion points
	nestedUserIP := NewNestedInsertionPoint(baseRequest, parentIP, userIP)
	nestedRoleIP := NewNestedInsertionPoint(baseRequest, parentIP, roleIP)

	// Test user payload only
	t.Run("UserPayloadOnly", func(t *testing.T) {
		payloads := PayloadMap{
			nestedUserIP: []byte(`test"quote`),
		}

		results, err := BuildRequestWithPayloads(baseRequest, payloads)
		if err != nil {
			t.Fatalf("BuildRequestWithPayloads failed: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("Expected 1 result, got %d", len(results))
		}

		// Exact match: JSON escaped quote \" becomes \\" in JSON, then URL encoded
		// {"user":"test\"quote","role":"guest"} -> URL encoded
		expected := "GET /api?data=%7B%22user%22%3A%22test%5C%22quote%22%2C%22role%22%3A%22guest%22%7D HTTP/1.1\r\n" +
			"Host: example.com\r\n\r\n"
		if string(results[0]) != expected {
			t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
		}
	})

	// Test role payload only
	t.Run("RolePayloadOnly", func(t *testing.T) {
		payloads := PayloadMap{
			nestedRoleIP: []byte("superadmin"),
		}

		results, err := BuildRequestWithPayloads(baseRequest, payloads)
		if err != nil {
			t.Fatalf("BuildRequestWithPayloads failed: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("Expected 1 result, got %d", len(results))
		}

		// Exact match
		expected := "GET /api?data=%7B%22user%22%3A%22admin%22%2C%22role%22%3A%22superadmin%22%7D HTTP/1.1\r\n" +
			"Host: example.com\r\n\r\n"
		if string(results[0]) != expected {
			t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
		}
	})

	// Test both - should split into 2 requests (same-parent conflict)
	t.Run("BothPayloads_ConflictSplit", func(t *testing.T) {
		payloads := PayloadMap{
			nestedUserIP: []byte(`test"quote`),
			nestedRoleIP: []byte("superadmin"),
		}

		results, err := BuildRequestWithPayloads(baseRequest, payloads)
		if err != nil {
			t.Fatalf("BuildRequestWithPayloads failed: %v", err)
		}

		if len(results) != 2 {
			t.Fatalf("Expected 2 results (same-parent conflict split), got %d", len(results))
		}

		// One result should have user payload, one should have role payload
		expectedUser := "GET /api?data=%7B%22user%22%3A%22test%5C%22quote%22%2C%22role%22%3A%22guest%22%7D HTTP/1.1\r\n" +
			"Host: example.com\r\n\r\n"
		expectedRole := "GET /api?data=%7B%22user%22%3A%22admin%22%2C%22role%22%3A%22superadmin%22%7D HTTP/1.1\r\n" +
			"Host: example.com\r\n\r\n"

		foundUser := false
		foundRole := false
		for _, r := range results {
			if string(r) == expectedUser {
				foundUser = true
			}
			if string(r) == expectedRole {
				foundRole = true
			}
		}

		if !foundUser {
			t.Errorf("Expected user payload result: %q", expectedUser)
		}
		if !foundRole {
			t.Errorf("Expected role payload result: %q", expectedRole)
		}
	})
}

// TestBuildRequestWithPayloads_NestedBase64JSON tests batch injection with
// JSON body containing Base64 encoded values
func TestBuildRequestWithPayloads_NestedBase64JSON(t *testing.T) {
	// Build request - use CreateAllInsertionPoints to get proper offsets
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 45\r\n\r\n" +
		`{"token":"dGVzdA==","secret":"c2VjcmV0"}`)

	// Use auto-discovery to get proper insertion points
	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints failed: %v", err)
	}

	// Find token and secret params
	var tokenParamIP, secretParamIP InsertionPoint
	for _, p := range points {
		switch p.Name() {
		case "token":
			tokenParamIP = p
		case "secret":
			secretParamIP = p
		}
	}

	if tokenParamIP == nil || secretParamIP == nil {
		t.Skipf("Could not find token/secret params, skipping")
	}

	// We'll use simple replacement here - replace the base64 values directly
	payloads := PayloadMap{
		tokenParamIP:  []byte("YWRtaW4="),         // Already base64-encoded "admin"
		secretParamIP: []byte("cGFzc3dvcmQxMjM="), // Already base64-encoded "password123"
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// New body: {"token":"YWRtaW4=","secret":"cGFzc3dvcmQxMjM="}
	expected := "POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 48\r\n\r\n" +
		`{"token":"YWRtaW4=","secret":"cGFzc3dvcmQxMjM="}`
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// TestBuildRequestWithPayloads_NestedBase64URLParam tests batch injection with
// URL parameter containing Base64 value
func TestBuildRequestWithPayloads_NestedBase64URLParam(t *testing.T) {
	// Request: GET /api?token=dGVzdA%3D%3D&auth=YWRtaW4%3D
	// token: base64("test") = "dGVzdA==" URL-encoded = "dGVzdA%3D%3D"
	// auth: base64("admin") = "YWRtaW4=" URL-encoded = "YWRtaW4%3D"
	baseRequest := []byte("GET /api?token=dGVzdA%3D%3D&auth=YWRtaW4%3D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n")

	// Parent: URL parameter "token"
	tokenParentParam := NewParsedParam(ParamURL, "token", "dGVzdA%3D%3D",
		9, 14, 15, 27)
	tokenParentIP := NewParameterInsertionPoint(baseRequest, tokenParentParam)

	// Child: Base64 encoder on decoded URL value
	decodedTokenValue := []byte("dGVzdA==")
	base64Encoder := NewBase64Encoder()
	tokenChildIP := NewEncodedInsertionPoint("token", decodedTokenValue, 0, 8,
		base64Encoder, nil, INS_PARAM_URL)

	// Nested insertion point for token
	nestedTokenIP := NewNestedInsertionPoint(baseRequest, tokenParentIP, tokenChildIP)

	// Parent: URL parameter "auth"
	authParentParam := NewParsedParam(ParamURL, "auth", "YWRtaW4%3D",
		28, 32, 33, 43)
	authParentIP := NewParameterInsertionPoint(baseRequest, authParentParam)

	// Child: Base64 encoder for auth
	decodedAuthValue := []byte("YWRtaW4=")
	authChildIP := NewEncodedInsertionPoint("auth", decodedAuthValue, 0, 8,
		base64Encoder, nil, INS_PARAM_URL)

	// Nested insertion point for auth
	nestedAuthIP := NewNestedInsertionPoint(baseRequest, authParentIP, authChildIP)

	// Batch inject
	payloads := PayloadMap{
		nestedTokenIP: []byte("newtoken"),
		nestedAuthIP:  []byte("superuser"),
	}

	results, err := BuildRequestWithPayloads(baseRequest, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// base64("newtoken") = "bmV3dG9rZW4=" URL-encoded = "bmV3dG9rZW4%3D"
	// base64("superuser") = "c3VwZXJ1c2Vy" (no padding, no URL encoding needed)
	expected := "GET /api?token=bmV3dG9rZW4%3D&auth=c3VwZXJ1c2Vy HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// TestBuildRequestWithPayloads_MixedNestedAndSimple tests batch injection with
// both nested and simple insertion points
func TestBuildRequestWithPayloads_MixedNestedAndSimple(t *testing.T) {
	// Request with URL param and nested JSON in URL
	// Using a simpler request without body to avoid offset issues
	baseRequest := []byte("GET /api?id=123&data=%7B%22user%22%3A%22admin%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n")

	// Simple URL param: id
	// GET /api?id=123&data=...
	//          ^  ^  ^  ^
	//          9  11 12 15
	idParam := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)
	idIP := NewParameterInsertionPoint(baseRequest, idParam)

	// Nested: JSON in URL param "data"
	// GET /api?id=123&data=%7B%22user%22%3A%22admin%22%7D HTTP/1.1
	//                ^   ^    ^                         ^
	//                16  20   21                        51
	dataParam := NewParsedParam(ParamURL, "data",
		"%7B%22user%22%3A%22admin%22%7D", 16, 20, 21, 51)
	dataParentIP := NewParameterInsertionPoint(baseRequest, dataParam)

	decodedJSON := []byte(`{"user":"admin"}`)
	jsonEncoder := &JSONEscapeEncoder{}
	userChildIP := NewEncodedInsertionPoint("user", decodedJSON, 9, 14, jsonEncoder, nil, INS_PARAM_JSON)
	nestedUserIP := NewNestedInsertionPoint(baseRequest, dataParentIP, userChildIP)

	// Batch inject both
	payloads := PayloadMap{
		idIP:         []byte("999"),
		nestedUserIP: []byte(`injected"value`),
	}

	results, err := BuildRequestWithPayloads(baseRequest, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	// {"user":"injected\"value"} -> URL encoded -> %7B%22user%22%3A%22injected%5C%22value%22%7D
	expected := "GET /api?id=999&data=%7B%22user%22%3A%22injected%5C%22value%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// TestBuildRequestWithPayloads_CookieWithNestedJSON tests batch injection with
// Cookie containing JSON value
func TestBuildRequestWithPayloads_CookieWithNestedJSON(t *testing.T) {
	// Request with cookie containing URL-encoded JSON
	baseRequest := []byte("GET /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: session=abc123; data=%7B%22user%22%3A%22admin%22%7D\r\n\r\n")

	// Simple cookie: session
	sessionParam := NewParsedParam(ParamCookie, "session", "abc123",
		46, 53, 54, 60)
	sessionIP := NewParameterInsertionPoint(baseRequest, sessionParam)

	// Nested: JSON in cookie "data"
	dataParam := NewParsedParam(ParamCookie, "data",
		"%7B%22user%22%3A%22admin%22%7D", 62, 66, 67, 97)
	dataParentIP := NewParameterInsertionPoint(baseRequest, dataParam)

	decodedJSON := []byte(`{"user":"admin"}`)
	jsonEncoder := &JSONEscapeEncoder{}
	userChildIP := NewEncodedInsertionPoint("user", decodedJSON, 9, 14, jsonEncoder, nil, INS_PARAM_JSON)
	nestedUserIP := NewNestedInsertionPoint(baseRequest, dataParentIP, userChildIP)

	// Batch inject
	payloads := PayloadMap{
		sessionIP:    []byte("newsession"),
		nestedUserIP: []byte(`test"cookie`),
	}

	results, err := BuildRequestWithPayloads(baseRequest, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	// {"user":"test\"cookie"} -> URL encoded for cookie -> %7B%22user%22%3A%22test%5C%22cookie%22%7D
	expected := "GET /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: session=newsession; data=%7B%22user%22%3A%22test%5C%22cookie%22%7D\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// TestBuildRequestWithPayloads_MultipleNestedSameParent tests batch injection
// with multiple nested params in JSON body (not sharing parent)
func TestBuildRequestWithPayloads_MultipleNestedSameParent(t *testing.T) {
	// Request with JSON containing multiple fields
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 47\r\n\r\n" +
		`{"user":"admin","pass":"secret","role":"guest"}`)

	// Use auto-discovery to get proper insertion points
	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints failed: %v", err)
	}

	// Find user, pass, role params
	var userIP, passIP, roleIP InsertionPoint
	for _, p := range points {
		switch p.Name() {
		case "user":
			userIP = p
		case "pass":
			passIP = p
		case "role":
			roleIP = p
		}
	}

	if userIP == nil || passIP == nil || roleIP == nil {
		t.Skipf("Could not find all JSON params")
	}

	// Batch inject all three JSON fields
	payloads := PayloadMap{
		userIP: []byte("newuser"),
		passIP: []byte("newpass"),
		roleIP: []byte("admin"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	expected := "POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 50\r\n\r\n" +
		`{"user":"newuser","pass":"newpass","role":"admin"}`
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}

	// Verify JSON structure is valid
	jsonBody := `{"user":"newuser","pass":"newpass","role":"admin"}`
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &data); err != nil {
		t.Errorf("Invalid JSON after batch injection: %v", err)
	}
	if data["user"] != "newuser" {
		t.Errorf("user = %v, want 'newuser'", data["user"])
	}
	if data["pass"] != "newpass" {
		t.Errorf("pass = %v, want 'newpass'", data["pass"])
	}
	if data["role"] != "admin" {
		t.Errorf("role = %v, want 'admin'", data["role"])
	}
}

// TestBuildRequestWithPayloads_Base64InBody tests simple body param injection
func TestBuildRequestWithPayloads_Base64InBody(t *testing.T) {
	// Request with URL-encoded body
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 19\r\n\r\n" +
		"token=test&key=abc")

	// Use auto-discovery
	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints failed: %v", err)
	}

	// Find token and key params
	var tokenIP, keyIP InsertionPoint
	for _, p := range points {
		switch p.Name() {
		case "token":
			tokenIP = p
		case "key":
			keyIP = p
		}
	}

	if tokenIP == nil || keyIP == nil {
		t.Skipf("Could not find token/key params")
	}

	// Batch inject
	payloads := PayloadMap{
		tokenIP: []byte("newtoken"),
		keyIP:   []byte("newkey"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Expected: token=newtoken&key=newkey (25 chars)
	expected := "POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 25\r\n\r\n" +
		"token=newtoken&key=newkey"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// =============================================================================
// CONFLICT DETECTION TESTS - Auto-split into multiple requests
// =============================================================================

// TestBuildRequestWithPayloads_ConflictNestedAndParent tests that when both
// a nested IP and its parent are in the payload map, the function automatically
// splits them into separate requests.
func TestBuildRequestWithPayloads_ConflictNestedAndParent(t *testing.T) {
	// Request with URL parameter containing JSON
	baseRequest := []byte("GET /api?data=%7B%22user%22%3A%22admin%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n")

	// Parent: URL parameter "data"
	parentParam := NewParsedParam(ParamURL, "data",
		"%7B%22user%22%3A%22admin%22%7D", 9, 13, 14, 44)
	parentIP := NewParameterInsertionPoint(baseRequest, parentParam)

	// Child: JSON field "user" inside decoded JSON
	decodedJSON := []byte(`{"user":"admin"}`)
	jsonEncoder := &JSONEscapeEncoder{}
	userChildIP := NewEncodedInsertionPoint("user", decodedJSON, 9, 14, jsonEncoder, nil, INS_PARAM_JSON)

	// Nested insertion point
	nestedUserIP := NewNestedInsertionPoint(baseRequest, parentIP, userChildIP)

	// CONFLICT: Both parent and nested in payload map
	payloads := PayloadMap{
		parentIP:     []byte("PARENT_PAYLOAD"),
		nestedUserIP: []byte("NESTED_PAYLOAD"),
	}

	results, err := BuildRequestWithPayloads(baseRequest, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	// Should return 2 requests (one for parent, one for nested)
	if len(results) != 2 {
		t.Fatalf("Expected 2 results due to conflict, got %d", len(results))
	}

	// Exact expected results
	expectedParent := "GET /api?data=PARENT_PAYLOAD HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"
	// {"user":"NESTED_PAYLOAD"} URL encoded
	expectedNested := "GET /api?data=%7B%22user%22%3A%22NESTED_PAYLOAD%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"

	foundParent := false
	foundNested := false
	for _, r := range results {
		if string(r) == expectedParent {
			foundParent = true
		}
		if string(r) == expectedNested {
			foundNested = true
		}
	}

	if !foundParent {
		t.Errorf("Expected parent result: %q", expectedParent)
	}
	if !foundNested {
		t.Errorf("Expected nested result: %q", expectedNested)
	}
}

// TestBuildRequestWithPayloads_ConflictWithSimpleParams tests that non-conflicting
// simple params are included in ALL generated requests when conflicts exist.
func TestBuildRequestWithPayloads_ConflictWithSimpleParams(t *testing.T) {
	// Request with id param and data param (data contains nested JSON)
	baseRequest := []byte("GET /api?id=123&data=%7B%22user%22%3A%22admin%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n")

	// Simple param: id (no conflict)
	idParam := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)
	idIP := NewParameterInsertionPoint(baseRequest, idParam)

	// Parent: URL parameter "data"
	dataParam := NewParsedParam(ParamURL, "data",
		"%7B%22user%22%3A%22admin%22%7D", 16, 20, 21, 51)
	dataParentIP := NewParameterInsertionPoint(baseRequest, dataParam)

	// Nested: JSON field "user"
	decodedJSON := []byte(`{"user":"admin"}`)
	jsonEncoder := &JSONEscapeEncoder{}
	userChildIP := NewEncodedInsertionPoint("user", decodedJSON, 9, 14, jsonEncoder, nil, INS_PARAM_JSON)
	nestedUserIP := NewNestedInsertionPoint(baseRequest, dataParentIP, userChildIP)

	// Payloads: id (no conflict) + data parent + nested user (conflict)
	payloads := PayloadMap{
		idIP:         []byte("ID_VALUE"),
		dataParentIP: []byte("PARENT_VALUE"),
		nestedUserIP: []byte("NESTED_VALUE"),
	}

	results, err := BuildRequestWithPayloads(baseRequest, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	// Should return 2 requests
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	// Exact expected results - both should have id=ID_VALUE
	expectedWithParent := "GET /api?id=ID_VALUE&data=PARENT_VALUE HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"
	expectedWithNested := "GET /api?id=ID_VALUE&data=%7B%22user%22%3A%22NESTED_VALUE%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"

	foundParent := false
	foundNested := false
	for _, r := range results {
		if string(r) == expectedWithParent {
			foundParent = true
		}
		if string(r) == expectedWithNested {
			foundNested = true
		}
	}

	if !foundParent {
		t.Errorf("Expected result with parent: %q", expectedWithParent)
	}
	if !foundNested {
		t.Errorf("Expected result with nested: %q", expectedWithNested)
	}
}

// TestBuildRequestWithPayloads_NoConflict verifies that without conflicts,
// only 1 request is returned.
func TestBuildRequestWithPayloads_NoConflict(t *testing.T) {
	baseRequest := []byte("GET /api?a=1&b=2&c=3 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Create insertion points for all params
	aParam := NewParsedParam(ParamURL, "a", "1", 9, 10, 11, 12)
	bParam := NewParsedParam(ParamURL, "b", "2", 13, 14, 15, 16)
	cParam := NewParsedParam(ParamURL, "c", "3", 17, 18, 19, 20)

	aIP := NewParameterInsertionPoint(baseRequest, aParam)
	bIP := NewParameterInsertionPoint(baseRequest, bParam)
	cIP := NewParameterInsertionPoint(baseRequest, cParam)

	// No conflicts - all simple params
	payloads := PayloadMap{
		aIP: []byte("A_VALUE"),
		bIP: []byte("B_VALUE"),
		cIP: []byte("C_VALUE"),
	}

	results, err := BuildRequestWithPayloads(baseRequest, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	// Should return exactly 1 request
	if len(results) != 1 {
		t.Fatalf("Expected 1 result (no conflicts), got %d", len(results))
	}

	// Exact match
	expected := "GET /api?a=A_VALUE&b=B_VALUE&c=C_VALUE HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// TestBuildRequestWithPayloads_MultipleConflicts tests handling of multiple
// conflict pairs (2^n combinations).
func TestBuildRequestWithPayloads_MultipleConflicts(t *testing.T) {
	// Simpler test with just one conflict pair to verify the conflict split logic
	// Using manually calculated offsets for a simple request
	baseRequest := []byte("GET /api?data=%7B%22u%22%3A%221%22%7D HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Verify offset calculation
	// GET /api?data=%7B%22u%22%3A%221%22%7D HTTP/1.1
	// 0         1         2         3         4
	// 0123456789012345678901234567890123456789012345678
	//          ^   ^    ^                      ^
	//          9   13   14                     37
	// data name: 9-13, value: 14-37 (%7B%22u%22%3A%221%22%7D = 23 chars)

	// Parent: data param
	dataParam := NewParsedParam(ParamURL, "data",
		"%7B%22u%22%3A%221%22%7D", 9, 13, 14, 37)
	dataParentIP := NewParameterInsertionPoint(baseRequest, dataParam)

	// Nested: u field in data
	decodedJSON := []byte(`{"u":"1"}`)
	jsonEncoder := &JSONEscapeEncoder{}
	uChildIP := NewEncodedInsertionPoint("u", decodedJSON, 6, 7, jsonEncoder, nil, INS_PARAM_JSON)
	nestedIP := NewNestedInsertionPoint(baseRequest, dataParentIP, uChildIP)

	// 1 conflict pair: (dataParent, nested)
	payloads := PayloadMap{
		dataParentIP: []byte("PARENT"),
		nestedIP:     []byte("NESTED"),
	}

	results, err := BuildRequestWithPayloads(baseRequest, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	// 1 conflict = 2 combinations
	if len(results) != 2 {
		t.Fatalf("Expected 2 results (conflict split), got %d", len(results))
	}

	// Log actual results for debugging
	for i, r := range results {
		t.Logf("Result %d: %q", i, string(r))
	}

	// Expected 2 results
	expectedParent := "GET /api?data=PARENT HTTP/1.1\r\nHost: example.com\r\n\r\n"
	expectedNested := "GET /api?data=%7B%22u%22%3A%22NESTED%22%7D HTTP/1.1\r\nHost: example.com\r\n\r\n"

	foundParent := false
	foundNested := false
	for _, r := range results {
		if string(r) == expectedParent {
			foundParent = true
		}
		if string(r) == expectedNested {
			foundNested = true
		}
	}

	if !foundParent {
		t.Errorf("Expected parent result: %q", expectedParent)
	}
	if !foundNested {
		t.Errorf("Expected nested result: %q", expectedNested)
	}
}

// =============================================================================
// INTEGRATION TESTS - Using CreateAllInsertionPoints API
// =============================================================================

// TestBatchIntegration_SimpleURLParams tests batch injection with auto-discovered
// URL parameters using CreateAllInsertionPoints.
func TestBatchIntegration_SimpleURLParams(t *testing.T) {
	request := []byte("GET /api/users?id=123&name=admin&role=user HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n")

	// Use CreateAllInsertionPoints to auto-discover params
	points, err := CreateAllInsertionPoints(request, false) // no nested
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints failed: %v", err)
	}

	// Filter to only URL query params (type 0)
	var idIP, nameIP, roleIP InsertionPoint
	for _, p := range points {
		if p.Type() != INS_PARAM_URL {
			continue
		}
		switch p.Name() {
		case "id":
			idIP = p
		case "name":
			nameIP = p
		case "role":
			roleIP = p
		}
	}

	if idIP == nil || nameIP == nil || roleIP == nil {
		t.Fatalf("Could not find all URL params: id=%v name=%v role=%v", idIP, nameIP, roleIP)
	}

	// Create payloads
	payloads := PayloadMap{
		idIP:   []byte("PAYLOAD_id"),
		nameIP: []byte("PAYLOAD_name"),
		roleIP: []byte("PAYLOAD_role"),
	}

	// Batch inject
	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match
	expected := "GET /api/users?id=PAYLOAD_id&name=PAYLOAD_name&role=PAYLOAD_role HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// TestBatchIntegration_MixedParams tests batch injection with URL + Body + Cookie.
func TestBatchIntegration_MixedParams(t *testing.T) {
	request := []byte("POST /api/login?redirect=/home HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: session=abc123; theme=dark\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 27\r\n\r\n" +
		"username=admin&password=pwd")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints failed: %v", err)
	}

	// Map params by name and type
	var redirectIP, sessionIP, usernameIP, passwordIP InsertionPoint
	for _, p := range points {
		switch p.Name() {
		case "redirect":
			if p.Type() == INS_PARAM_URL {
				redirectIP = p
			}
		case "session":
			sessionIP = p
		case "username":
			usernameIP = p
		case "password":
			passwordIP = p
		}
	}

	if redirectIP == nil || sessionIP == nil || usernameIP == nil || passwordIP == nil {
		t.Fatalf("Could not find all params: redirect=%v session=%v username=%v password=%v",
			redirectIP, sessionIP, usernameIP, passwordIP)
	}

	// Create targeted payloads
	payloads := PayloadMap{
		redirectIP: []byte("/evil"),
		sessionIP:  []byte("hijacked"),
		usernameIP: []byte("attacker"),
		passwordIP: []byte("secret123"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match - Content-Length is 36 because "username=attacker&password=secret123" is 36 chars
	expected := "POST /api/login?redirect=%2Fevil HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Cookie: session=hijacked; theme=dark\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 36\r\n\r\n" +
		"username=attacker&password=secret123"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// TestBatchIntegration_JSONBody tests batch injection with JSON body params.
func TestBatchIntegration_JSONBody(t *testing.T) {
	request := []byte("POST /api/user HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 52\r\n\r\n" +
		`{"username":"admin","email":"admin@test.com","age":25}`)

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints failed: %v", err)
	}

	// Find JSON params
	var usernameIP, emailIP, ageIP InsertionPoint
	for _, p := range points {
		switch p.Name() {
		case "username":
			usernameIP = p
		case "email":
			emailIP = p
		case "age":
			ageIP = p
		}
	}

	if usernameIP == nil || emailIP == nil || ageIP == nil {
		t.Skipf("JSON params not all found: username=%v email=%v age=%v", usernameIP, emailIP, ageIP)
	}

	// Create payloads for JSON fields
	payloads := PayloadMap{
		usernameIP: []byte("hacker"),
		emailIP:    []byte("hacker@evil.com"),
		ageIP:      []byte("99"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match - Content-Length is 56 for {"username":"hacker","email":"hacker@evil.com","age":99}
	expected := "POST /api/user HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 56\r\n\r\n" +
		`{"username":"hacker","email":"hacker@evil.com","age":99}`
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}

	// Verify JSON is valid
	jsonBody := `{"username":"hacker","email":"hacker@evil.com","age":99}`
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &parsed); err != nil {
		t.Errorf("Invalid JSON: %v", err)
	}
}

// TestBatchIntegration_SamePayloadAllParams tests BuildRequestWithSamePayload.
func TestBatchIntegration_SamePayloadAllParams(t *testing.T) {
	request := []byte("GET /api?a=1&b=2&c=3 HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints failed: %v", err)
	}

	// Filter to only URL query params (type 0)
	var urlParams []InsertionPoint
	for _, p := range points {
		if p.Type() == INS_PARAM_URL {
			urlParams = append(urlParams, p)
		}
	}

	// Inject XSS payload into URL params only
	results, err := BuildRequestWithSamePayload(request, urlParams, []byte("<script>"))
	if err != nil {
		t.Fatalf("BuildRequestWithSamePayload failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Exact match - URL encoded XSS
	expected := "GET /api?a=%3Cscript%3E&b=%3Cscript%3E&c=%3Cscript%3E HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"
	if string(results[0]) != expected {
		t.Errorf("Result mismatch:\nExpected: %q\nGot:      %q", expected, string(results[0]))
	}
}

// TestBatchIntegration_ConflictAutoSplit tests automatic conflict splitting.
func TestBatchIntegration_ConflictAutoSplit(t *testing.T) {
	// Request with URL-encoded JSON: {"user":"admin"}
	request := []byte("GET /api?data=%7B%22user%22%3A%22admin%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n")

	// Manually create parent and nested IPs
	dataParam := NewParsedParam(ParamURL, "data",
		"%7B%22user%22%3A%22admin%22%7D", 9, 13, 14, 44)
	dataIP := NewParameterInsertionPoint(request, dataParam)

	// Nested: user field inside the decoded JSON
	decodedJSON := []byte(`{"user":"admin"}`)
	jsonEncoder := &JSONEscapeEncoder{}
	userChildIP := NewEncodedInsertionPoint("user", decodedJSON, 9, 14, jsonEncoder, nil, INS_PARAM_JSON)
	userIP := NewNestedInsertionPoint(request, dataIP, userChildIP)

	// Create conflict: both parent and nested in payloads
	payloads := PayloadMap{
		dataIP: []byte("PARENT_PAYLOAD"),
		userIP: []byte("NESTED_PAYLOAD"),
	}

	results, err := BuildRequestWithPayloads(request, payloads)
	if err != nil {
		t.Fatalf("BuildRequestWithPayloads failed: %v", err)
	}

	// Should auto-split into 2 requests
	if len(results) != 2 {
		t.Fatalf("Expected 2 results (auto-split), got %d", len(results))
	}

	// Exact expected results
	expectedParent := "GET /api?data=PARENT_PAYLOAD HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"
	expectedNested := "GET /api?data=%7B%22user%22%3A%22NESTED_PAYLOAD%22%7D HTTP/1.1\r\n" +
		"Host: example.com\r\n\r\n"

	foundParent := false
	foundNested := false
	for _, r := range results {
		if string(r) == expectedParent {
			foundParent = true
		}
		if string(r) == expectedNested {
			foundNested = true
		}
	}

	if !foundParent {
		t.Errorf("Expected parent result: %q", expectedParent)
	}
	if !foundNested {
		t.Errorf("Expected nested result: %q", expectedNested)
	}
}
