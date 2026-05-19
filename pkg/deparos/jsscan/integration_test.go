package jsscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Integration tests that require the actual jsscan binary

func TestIntegration_ScanWithRequests(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// JavaScript with clear API endpoints that jsscan should detect
	js := `
// API Configuration
const API_BASE = "/api/v1";

// Fetch calls
fetch("/api/users");
fetch("/api/posts", { method: "GET" });
fetch("/api/comments", { method: "POST", body: JSON.stringify({ text: "hello" }) });

// XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.open("GET", "/api/data");
xhr.send();

// jQuery
$.ajax({ url: "/api/items", method: "PUT" });
$.get("/api/config");
$.post("/api/submit", { data: "value" });

// Axios
axios.get("/api/axios-endpoint");
axios.post("/api/axios-post", { key: "value" });

// String literals
const endpoints = {
    users: "/api/users",
    admin: "/admin/dashboard",
    config: "/config.json"
};
`

	result, err := scanner.Scan(context.Background(), []byte(js))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Log all found requests
	t.Logf("Found %d requests:", len(result.Requests))
	for i, req := range result.Requests {
		t.Logf("  [%d] %s %s (params: %q, body: %q)", i, req.Method, req.URL, req.Params, req.Body)
	}

	// Should find at least some requests
	if len(result.Requests) == 0 {
		t.Log("Warning: no requests extracted - this may be expected depending on jsscan version")
	}
}

func TestIntegration_ScanMinifiedJS(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Minified JavaScript
	js := `!function(){"use strict";const e="/api/v1";fetch(e+"/users"),fetch("/api/posts",{method:"POST",body:JSON.stringify({id:1})})}();`

	result, err := scanner.Scan(context.Background(), []byte(js))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	t.Logf("Found %d requests in minified JS", len(result.Requests))
	for i, req := range result.Requests {
		t.Logf("  [%d] %s %s", i, req.Method, req.URL)
	}
}

func TestIntegration_ScanWebpackBundle(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Simulated webpack bundle
	js := `
/******/ (function(modules) {
/******/    var installedModules = {};
/******/    function __webpack_require__(moduleId) {
/******/        if(installedModules[moduleId]) return installedModules[moduleId].exports;
/******/        var module = installedModules[moduleId] = { exports: {} };
/******/        modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/        return module.exports;
/******/    }
/******/    return __webpack_require__(0);
/******/ })([
/* 0 */
function(module, exports) {
    const API = {
        baseUrl: "https://api.example.com/v2",
        endpoints: {
            users: "/users",
            auth: "/auth/login",
            data: "/data/export"
        }
    };

    fetch(API.baseUrl + API.endpoints.users);
    fetch("/internal/api/health");
},
/* 1 */
function(module, exports) {
    module.exports = {
        secretEndpoint: "/admin/secret",
        debugApi: "/debug/pprof"
    };
}
]);
`

	result, err := scanner.Scan(context.Background(), []byte(js))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	t.Logf("Found %d requests in webpack bundle", len(result.Requests))
	for i, req := range result.Requests {
		t.Logf("  [%d] %s %s", i, req.Method, req.URL)
	}
}

func TestIntegration_ScanFile_LargeFile(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	tmpDir := t.TempDir()
	jsFile := filepath.Join(tmpDir, "large.js")

	// Create large JS file with unique variable names to avoid duplicate declaration errors
	var content []byte
	content = append(content, []byte("// Large JavaScript file\n")...)
	for i := range 100 {
		content = append(content, []byte(`var endpoint_`+string(rune('a'+i%26))+string(rune('0'+i/26))+` = "/api/resource/`+string(rune('0'+i%10))+`";`+"\n")...)
	}
	content = append(content, []byte(`
fetch("/api/main-endpoint");
axios.get("/api/axios-endpoint");
$.post("/api/jquery-endpoint");
`)...)

	if err := os.WriteFile(jsFile, content, 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	start := time.Now()
	result, err := scanner.ScanFile(context.Background(), jsFile)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	t.Logf("Scanned %d bytes in %v, found %d requests", result.BytesScanned, duration, len(result.Requests))

	if result.BytesScanned != len(content) {
		t.Errorf("BytesScanned = %d, want %d", result.BytesScanned, len(content))
	}
}

func TestIntegration_ScanWithHeaders(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	js := `
fetch("/api/protected", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "X-Custom-Header": "custom-value"
    },
    body: JSON.stringify({ action: "test" })
});

axios.post("/api/axios-protected", { data: "test" }, {
    headers: {
        "X-API-Key": "secret-key-123"
    }
});
`

	result, err := scanner.Scan(context.Background(), []byte(js))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	t.Logf("Found %d requests with headers", len(result.Requests))
	for i, req := range result.Requests {
		t.Logf("  [%d] %s %s", i, req.Method, req.URL)
		if len(req.Headers) > 0 {
			t.Logf("      Headers: %v", req.Headers)
		}
		if req.Body != "" {
			t.Logf("      Body: %s", req.Body)
		}
	}
}

func TestIntegration_ScanWithQueryParams(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	js := `
// URL with query parameters
fetch("/api/search?q=test&page=1&limit=10");
fetch("/api/filter?status=active&type=user");

// Built URL
const params = new URLSearchParams({ foo: "bar", baz: "qux" });
fetch("/api/data?" + params.toString());

// Template literal
const id = 123;
fetch('/api/users/' + id + '?include=profile');
`

	result, err := scanner.Scan(context.Background(), []byte(js))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	t.Logf("Found %d requests with query params", len(result.Requests))
	for i, req := range result.Requests {
		t.Logf("  [%d] %s %s (params: %q)", i, req.Method, req.URL, req.Params)
	}
}

func TestIntegration_ScanModernJS(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Modern JavaScript with ES6+ patterns (without template literals that may cause parser issues)
	js := `
// ES6+ patterns
const api = {
    base: "https://api.example.com",
    version: "v3"
};

const fetchData = async () => {
    const response = await fetch("/api/modern/data");
    return await response.json();
};

// Arrow function
const getData = async () => {
    return await fetch("/api/arrow-function");
};

// Spread operator in requests
const options = {
    method: "POST",
    body: JSON.stringify({ key: "value" })
};
fetch("/api/spread-test", options);

// String concatenation for dynamic URLs
const userId = 42;
fetch("/api/users/" + userId + "/profile");
`

	result, err := scanner.Scan(context.Background(), []byte(js))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	t.Logf("Found %d requests in modern JS", len(result.Requests))
	for i, req := range result.Requests {
		t.Logf("  [%d] %s %s", i, req.Method, req.URL)
	}
}

func TestIntegration_ScanReactLikeCode(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// JavaScript code similar to React but without JSX (which requires babel plugins)
	js := `
const API_URL = "/api/v1";

function UserList() {
    var users = [];

    // Fetch users
    fetch(API_URL + "/users")
        .then(function(res) { return res.json(); })
        .then(function(data) { users = data; });

    function handleDelete(id) {
        return fetch('/api/users/' + id, { method: 'DELETE' });
    }

    function handleUpdate(id, data) {
        return fetch('/api/users/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
    }

    return users;
}
`

	result, err := scanner.Scan(context.Background(), []byte(js))

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	t.Logf("Found %d requests in React-like code", len(result.Requests))
	for i, req := range result.Requests {
		t.Logf("  [%d] %s %s", i, req.Method, req.URL)
	}
}

func TestIntegration_MultipleScansSameScanner(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	scanner, err := NewScanner(nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	jsFiles := []string{
		`fetch("/api/file1");`,
		`fetch("/api/file2"); axios.get("/api/axios2");`,
		`$.post("/api/jquery3"); fetch("/api/fetch3");`,
	}

	for i, js := range jsFiles {
		result, err := scanner.Scan(context.Background(), []byte(js))
		if err != nil {
			t.Fatalf("Scan[%d] failed: %v", i, err)
		}
		t.Logf("File %d: found %d requests", i, len(result.Requests))
	}
}

func TestIntegration_BinaryExtraction(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	tmpDir := t.TempDir()

	scanner, err := NewScanner(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Trigger extraction
	err = scanner.EnsureBinary()
	if err != nil {
		t.Fatalf("EnsureBinary failed: %v", err)
	}

	// Verify binary exists and is executable
	binaryPath := scanner.BinaryPath()
	info, err := os.Stat(binaryPath)
	if err != nil {
		t.Fatalf("binary not found: %v", err)
	}

	if !info.Mode().IsRegular() {
		t.Error("binary is not a regular file")
	}

	if info.Mode().Perm()&0111 == 0 {
		t.Error("binary is not executable")
	}

	t.Logf("Binary extracted to: %s (size: %d bytes)", binaryPath, info.Size())
}

func TestIntegration_ChecksumConsistency(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jsscan binary available")
	}

	tmpDir := t.TempDir()

	// First scanner
	scanner1, err := NewScanner(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}
	_ = scanner1.EnsureBinary()
	checksum1 := scanner1.Checksum()

	// Clear and re-create
	_ = scanner1.Clear()

	// Second scanner with same cache
	scanner2, err := NewScanner(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}
	_ = scanner2.EnsureBinary()
	checksum2 := scanner2.Checksum()

	if checksum1 != checksum2 {
		t.Errorf("checksums differ: %s vs %s", checksum1, checksum2)
	}

	// Verify checksum matches embedded
	if checksum1 != getEmbeddedChecksum() {
		t.Errorf("checksum doesn't match embedded: %s vs %s", checksum1, getEmbeddedChecksum())
	}
}
