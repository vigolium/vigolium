package jsscan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseJsscanOutput_EmptyOutput(t *testing.T) {
	requests, code, err := parseJsscanOutput([]byte{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(requests) != 0 {
		t.Errorf("expected 0 requests, got %d", len(requests))
	}
	if code != nil {
		t.Error("expected nil code")
	}
}

func TestParseJsscanOutput_ExtractedRequests(t *testing.T) {
	output := `{"type":"extractedRequest","url":"/api/users","method":"GET","params":"","body":"","headers":null,"cookies":null}
{"type":"extractedRequest","url":"/api/posts","method":"POST","params":"","body":"{\"title\":\"test\"}","headers":["Content-Type: application/json"],"cookies":null}`

	requests, code, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}

	if requests[0].URL != "/api/users" {
		t.Errorf("request[0].URL = %q, want /api/users", requests[0].URL)
	}
	if requests[0].Method != "GET" {
		t.Errorf("request[0].Method = %q, want GET", requests[0].Method)
	}

	if requests[1].URL != "/api/posts" {
		t.Errorf("request[1].URL = %q, want /api/posts", requests[1].URL)
	}
	if requests[1].Method != "POST" {
		t.Errorf("request[1].Method = %q, want POST", requests[1].Method)
	}
	if requests[1].Body != `{"title":"test"}` {
		t.Errorf("request[1].Body = %q", requests[1].Body)
	}
	if len(requests[1].Headers) != 1 {
		t.Errorf("len(request[1].Headers) = %d, want 1", len(requests[1].Headers))
	}

	if code != nil {
		t.Error("expected nil code")
	}
}

func TestParseJsscanOutput_CodeRecord(t *testing.T) {
	output := `{"type":"code","filename":"bundle.js","content":"function test() { return 1; }"}`

	requests, code, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(requests) != 0 {
		t.Errorf("expected 0 requests, got %d", len(requests))
	}

	if code == nil {
		t.Fatal("expected non-nil code")
	}
	if code.Filename != "bundle.js" {
		t.Errorf("code.Filename = %q, want bundle.js", code.Filename)
	}
	if code.Content != "function test() { return 1; }" {
		t.Errorf("code.Content = %q", code.Content)
	}
}

func TestParseJsscanOutput_MixedRecords(t *testing.T) {
	output := `{"type":"extractedRequest","url":"/api/v1","method":"GET","params":"","body":"","headers":null,"cookies":null}
{"type":"code","filename":"app.js","content":"const API = '/api/v1';"}
{"type":"extractedRequest","url":"/api/v2","method":"POST","params":"","body":"","headers":null,"cookies":null}`

	requests, code, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(requests) != 2 {
		t.Errorf("expected 2 requests, got %d", len(requests))
	}
	if code == nil {
		t.Fatal("expected non-nil code")
	}
	if code.Filename != "app.js" {
		t.Errorf("code.Filename = %q, want app.js", code.Filename)
	}
}

func TestParseJsscanOutput_InvalidJSON(t *testing.T) {
	output := `{"type":"extractedRequest","url":"/api/valid","method":"GET","params":"","body":"","headers":null,"cookies":null}
this is not valid json
{"type":"extractedRequest","url":"/api/also-valid","method":"POST","params":"","body":"","headers":null,"cookies":null}`

	requests, _, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invalid lines should be skipped
	if len(requests) != 2 {
		t.Errorf("expected 2 valid requests, got %d", len(requests))
	}
}

func TestParseJsscanOutput_EmptyLines(t *testing.T) {
	output := `{"type":"extractedRequest","url":"/api/test","method":"GET","params":"","body":"","headers":null,"cookies":null}


{"type":"extractedRequest","url":"/api/test2","method":"GET","params":"","body":"","headers":null,"cookies":null}
`

	requests, _, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(requests) != 2 {
		t.Errorf("expected 2 requests, got %d", len(requests))
	}
}

func TestParseJsscanOutput_UnknownType(t *testing.T) {
	output := `{"type":"extractedRequest","url":"/api/test","method":"GET","params":"","body":"","headers":null,"cookies":null}
{"type":"unknownType","foo":"bar"}
{"type":"extractedRequest","url":"/api/test2","method":"GET","params":"","body":"","headers":null,"cookies":null}`

	requests, _, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unknown types should be ignored
	if len(requests) != 2 {
		t.Errorf("expected 2 requests, got %d", len(requests))
	}
}

func TestParseJsscanOutput_MalformedRequest(t *testing.T) {
	output := `{"type":"extractedRequest","url":"/api/valid","method":"GET","params":"","body":"","headers":null,"cookies":null}
{"type":"extractedRequest","url":123}
{"type":"extractedRequest","url":"/api/also-valid","method":"POST","params":"","body":"","headers":null,"cookies":null}`

	requests, _, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Malformed records should be skipped (url should be string, not number)
	if len(requests) != 2 {
		t.Errorf("expected 2 valid requests, got %d", len(requests))
	}
}

func TestParseJsscanOutput_SpecialCharacters(t *testing.T) {
	output := `{"type":"extractedRequest","url":"/api/search?q=hello%20world","method":"GET","params":"q=hello world","body":"","headers":["X-Custom: value with \"quotes\""],"cookies":null}`

	requests, _, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}

	if requests[0].Params != "q=hello world" {
		t.Errorf("Params = %q, want 'q=hello world'", requests[0].Params)
	}
}

func TestParseJsscanOutput_CompleteRequest(t *testing.T) {
	output := `{"type":"extractedRequest","url":"https://api.example.com/users","method":"POST","params":"page=1","body":"{\"name\":\"test\",\"email\":\"test@example.com\"}","headers":["Content-Type: application/json","Authorization: Bearer token123"],"cookies":["session=abc123","csrf=xyz789"]}`

	requests, _, err := parseJsscanOutput([]byte(output))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}

	req := requests[0]
	if req.URL != "https://api.example.com/users" {
		t.Errorf("URL = %q", req.URL)
	}
	if req.Method != "POST" {
		t.Errorf("Method = %q", req.Method)
	}
	if req.Params != "page=1" {
		t.Errorf("Params = %q", req.Params)
	}
	if !strings.Contains(req.Body, "test@example.com") {
		t.Errorf("Body = %q", req.Body)
	}
	if len(req.Headers) != 2 {
		t.Errorf("len(Headers) = %d", len(req.Headers))
	}
	if len(req.Cookies) != 2 {
		t.Errorf("len(Cookies) = %d", len(req.Cookies))
	}
}

func TestScanner_ScanEmptyContent(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	result, err := scanner.Scan(context.Background(), []byte{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Requests) != 0 {
		t.Errorf("expected 0 requests for empty content, got %d", len(result.Requests))
	}

	if result.BytesScanned != 0 {
		t.Errorf("BytesScanned = %d, want 0", result.BytesScanned)
	}
}

func TestScanner_NewScannerWithNilConfig(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)

	if err != nil {
		t.Fatalf("NewScanner(nil) failed: %v", err)
	}

	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestScanner_NewScannerWithCustomCacheDir(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "custom-cache")

	scanner, err := NewScanner(&Config{CacheDir: cacheDir})

	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}

	// Verify cache dir was created
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		t.Error("cache directory was not created")
	}
}

func TestScanner_Checksum(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Before extraction, checksum should be empty
	checksum := scanner.Checksum()
	if checksum != "" {
		t.Errorf("expected empty checksum before extraction, got %q", checksum)
	}

	// Trigger extraction
	err = scanner.EnsureBinary()
	if err != nil {
		t.Fatalf("EnsureBinary failed: %v", err)
	}

	// After extraction, checksum should be non-empty
	checksum = scanner.Checksum()
	if checksum == "" {
		t.Error("expected non-empty checksum after extraction")
	}

	if len(checksum) != 64 { // SHA256 hex length
		t.Errorf("checksum length = %d, want 64", len(checksum))
	}
}

func TestScanner_BinaryPath(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Before extraction, path should be empty
	path := scanner.BinaryPath()
	if path != "" {
		t.Errorf("expected empty path before extraction, got %q", path)
	}

	// Trigger extraction
	err = scanner.EnsureBinary()
	if err != nil {
		t.Fatalf("EnsureBinary failed: %v", err)
	}

	// After extraction, path should be non-empty
	path = scanner.BinaryPath()
	if path == "" {
		t.Error("expected non-empty path after extraction")
	}

	// Path should exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("binary path %q does not exist", path)
	}
}

func TestScanner_Clear(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")

	scanner, err := NewScanner(&Config{CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Extract binary
	err = scanner.EnsureBinary()
	if err != nil {
		t.Fatalf("EnsureBinary failed: %v", err)
	}

	path := scanner.BinaryPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("binary should exist after extraction")
	}

	// Clear cache
	err = scanner.Clear()
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Binary should be removed
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("binary should be removed after Clear")
	}

	// Checksum should be empty
	if scanner.Checksum() != "" {
		t.Error("checksum should be empty after Clear")
	}
}

func TestScanner_ScanReader(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	content := []byte(`var api = "/api/test";`)
	reader := bytes.NewReader(content)

	result, err := scanner.ScanReader(context.Background(), reader)

	if err != nil {
		t.Fatalf("ScanReader failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.BytesScanned != len(content) {
		t.Errorf("BytesScanned = %d, want %d", result.BytesScanned, len(content))
	}
}

func TestScanner_ScanFile(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	tmpDir := t.TempDir()
	jsFile := filepath.Join(tmpDir, "test.js")
	content := []byte(`const endpoint = "/api/users";`)

	if err := os.WriteFile(jsFile, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	result, err := scanner.ScanFile(context.Background(), jsFile)

	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.BytesScanned != len(content) {
		t.Errorf("BytesScanned = %d, want %d", result.BytesScanned, len(content))
	}
}

func TestScanner_ScanFile_NotExists(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	_, err = scanner.ScanFile(context.Background(), "/nonexistent/file.js")

	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestScanner_ContextCancellation(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = scanner.Scan(ctx, []byte(`var x = 1;`))

	// The behavior depends on timing - either context.Canceled or scan completes
	// We just verify it doesn't panic
	_ = err // Error is acceptable if scan completed before cancellation
}

func TestScanner_ConcurrentScans(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 5
	errs := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			content := []byte(`var endpoint = "/api/v` + string(rune('0'+id)) + `";`)
			_, scanErr := scanner.Scan(context.Background(), content)
			if scanErr != nil {
				errs <- scanErr
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent scan error: %v", err)
	}
}

func TestScanner_ScanDuration(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	result, err := scanner.Scan(context.Background(), []byte(`var x = 1;`))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.ScanDuration <= 0 {
		t.Errorf("ScanDuration = %v, expected positive duration", result.ScanDuration)
	}

	if result.ScanDuration > 30*time.Second {
		t.Errorf("ScanDuration = %v, seems too long", result.ScanDuration)
	}
}

func TestScanner_RealJavaScriptContent(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Real-world JavaScript with API calls
	jsContent := `
(function() {
    const API_BASE = "https://api.example.com/v1";

    async function fetchUsers() {
        const response = await fetch(API_BASE + "/users", {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + getToken()
            }
        });
        return response.json();
    }

    async function createUser(data) {
        const response = await fetch(API_BASE + "/users", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });
        return response.json();
    }

    // API endpoints
    const endpoints = {
        users: "/api/users",
        posts: "/api/posts",
        comments: "/api/comments"
    };
})();
`

	result, err := scanner.Scan(context.Background(), []byte(jsContent))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.BytesScanned != len(jsContent) {
		t.Errorf("BytesScanned = %d, want %d", result.BytesScanned, len(jsContent))
	}

	// Log extracted requests for debugging
	t.Logf("Extracted %d requests", len(result.Requests))
	for i, req := range result.Requests {
		t.Logf("  [%d] %s %s", i, req.Method, req.URL)
	}
}

func TestScanner_LargeContent(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Generate large JS content
	var builder strings.Builder
	for i := 0; i < 1000; i++ {
		builder.WriteString(`var endpoint` + string(rune('0'+i%10)) + ` = "/api/resource/` + string(rune('0'+i%10)) + `";` + "\n")
	}
	content := []byte(builder.String())

	result, err := scanner.Scan(context.Background(), content)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.BytesScanned != len(content) {
		t.Errorf("BytesScanned = %d, want %d", result.BytesScanned, len(content))
	}
}
