package jstangle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newScanService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(nil)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func TestCleanupStaleTempFilesRemovesFilesAndArtifactDirectories(t *testing.T) {
	oldFile, err := os.CreateTemp("", "jstangle-stale-test-*.js")
	if err != nil {
		t.Fatal(err)
	}
	oldFilePath := oldFile.Name()
	_ = oldFile.Close()
	oldDir, err := os.MkdirTemp("", "jstangle-job-stale-test-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "artifact.js"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(oldFilePath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(oldDir, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	staleCleanupOnce = sync.Once{}
	cleanupStaleTempFiles()
	for _, path := range []string{oldFilePath, oldDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("stale jstangle path still exists: %s", path)
			_ = os.RemoveAll(path)
		}
	}
}

func TestScanResultFromAnalysis_V2Envelope(t *testing.T) {
	output := `{"type":"analysisResult","schemaVersion":2,"jobId":"job-1","profile":"endpoints","tool":{"version":"1.0.0","sourceHash":"abc"},"source":{"url":"https://app.test/app.js","contentSha256":"def","byteLength":42},"stats":{"status":"complete","inputBytes":42,"durationMs":1,"recordCounts":{"httpRequest":1},"stageMetrics":[]},"diagnostics":[],"records":[{"kind":"httpRequest","id":"http-1","url":{"rendered":"/api/${id}","static":false,"variables":[{"name":"id","placeholder":"${id}"}]},"method":{"rendered":"POST","static":true,"variables":[]},"query":[{"name":{"rendered":"page","static":true,"variables":[]},"value":{"rendered":"${page}","static":false,"variables":[{"name":"page","placeholder":"${page}"}]}}],"headers":[{"name":{"rendered":"Content-Type","static":true,"variables":[]},"value":{"rendered":"application/json","static":true,"variables":[]}}],"cookies":[],"body":{"kind":"json","value":{"rendered":"{\"id\":\"${id}\"}","static":false,"variables":[]}},"client":"fetch","provenance":{"extractor":"fetch","confidence":"high","start":{"line":3,"column":2}}},{"kind":"futureFact","id":"future-1"}],"artifacts":[]}`
	var analysis AnalysisResultV2
	if err := json.Unmarshal([]byte(output), &analysis); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	res := scanResultFromAnalysis(&analysis, nil)
	if res.Analysis == nil || res.Analysis.Source.URL != "https://app.test/app.js" {
		t.Fatalf("missing typed envelope: %#v", res.Analysis)
	}
	if len(res.RequestFacts) != 1 || res.RequestFacts[0].Provenance.Extractor != "fetch" {
		t.Fatalf("unexpected typed request facts: %#v", res.RequestFacts)
	}
	if len(res.Requests) != 1 || res.Requests[0].Params != "page=${page}" || res.Requests[0].Body == "" {
		t.Fatalf("legacy projection lost typed fields: %#v", res.Requests)
	}
	if res.UnknownRecords != 1 || len(res.UnknownRecordData) != 1 {
		t.Fatalf("future record was not preserved: count=%d data=%d", res.UnknownRecords, len(res.UnknownRecordData))
	}
}

func TestAppendAnalysisRecordCapabilityFamilies(t *testing.T) {
	result := &ScanResult{}
	records := []any{
		GraphQLOperationFact{Kind: "graphqlOperation", ID: "g1", OperationType: "mutation", Transport: "http", Variables: []GraphQLVariableTemplate{}},
		WebSocketFact{Kind: "websocket", ID: "w1", URL: ValueTemplate{Rendered: "wss://example.test/ws"}, Subprotocols: []string{"graphql-transport-ws"}},
		EventSourceFact{Kind: "eventSource", ID: "e1", URL: ValueTemplate{Rendered: "/events"}, WithCredentials: true},
		ClientRouteFact{Kind: "clientRoute", ID: "r1", Path: ValueTemplate{Rendered: "/users/:id"}, RouteType: "page"},
		BrowserSecurityFlowFact{Kind: "browserSecurityFlow", ID: "b1", FlowType: "openRedirect", Source: "location.hash", Sink: "location.href"},
		DomFlowFact{Kind: "domFlow", ID: "d1", FlowType: "openRedirect", Source: "location.hash", Sink: "location.href"},
	}
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		appendAnalysisRecord(result, encoded)
	}
	if len(result.GraphQLOperations) != 1 || len(result.WebSockets) != 1 || len(result.EventSources) != 1 ||
		len(result.ClientRoutes) != 1 || len(result.BrowserFlows) != 1 || len(result.DomFlows) != 1 {
		t.Fatalf("capability records were not decoded: %#v", result)
	}
	if result.DomFlows[0].FlowType != "openRedirect" {
		t.Fatalf("DOM flow classification was lost: %#v", result.DomFlows[0])
	}
	if result.UnknownRecords != 0 || result.MalformedRecords != 0 {
		t.Fatalf("known records counted as unknown/malformed: %#v", result)
	}
}

func TestLoadArtifactsRejectsPathEscape(t *testing.T) {
	jobDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.js")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := &ScanResult{Artifacts: []ArtifactDescriptor{{
		ArtifactType: "beautifiedSource", Path: outside,
		SHA256: "00", ByteLength: 6,
	}}}
	if err := loadArtifacts(result, jobDir, 1024); err == nil {
		t.Fatal("expected an artifact path escape error")
	}
}

// TestScanner_LargeBeautifyOutputNotTruncated guards that a large (>64KB)
// beautified document survives the worker's length-prefixed framing + artifact
// transfer intact (regression: earlier stdout-pipe capture truncated it).
func TestScanner_LargeBeautifyOutputNotTruncated(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	scanner := newScanService(t)

	// Single-line minified script; unminifying it (one statement per line) yields a
	// document far larger than the 64KB pipe buffer.
	var b strings.Builder
	b.WriteString("(function(){")
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&b, "var a%d=fn(%d);", i, i)
	}
	b.WriteString("})();")
	input := []byte(b.String())

	res, err := scanner.ScanWithOptions(context.Background(), input, ScanOptions{Beautify: true})
	if err != nil {
		t.Fatalf("ScanWithOptions failed: %v", err)
	}
	if !res.HasBeautified() {
		t.Fatal("expected a beautified record for a large minified script (regression: pipe truncated the >64KB line)")
	}
	if got := len(res.Beautified.Content); got <= 65535 {
		t.Fatalf("beautified content truncated at pipe buffer: got %d bytes, want > 65535", got)
	}
}

func TestScanner_NewScannerWithNilConfig(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
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
		t.Skip("skipping: no valid jstangle binary available")
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
		t.Skip("skipping: no valid jstangle binary available")
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
		t.Skip("skipping: no valid jstangle binary available")
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
		t.Skip("skipping: no valid jstangle binary available")
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
		t.Skip("skipping: no valid jstangle binary available")
	}

	scanner := newScanService(t)

	content := []byte(`var api = "/api/test";`)

	result, err := scanner.Scan(context.Background(), content)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
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
		t.Skip("skipping: no valid jstangle binary available")
	}

	content := []byte(`const endpoint = "/api/users";`)

	scanner := newScanService(t)

	result, err := scanner.Scan(context.Background(), content)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.BytesScanned != len(content) {
		t.Errorf("BytesScanned = %d, want %d", result.BytesScanned, len(content))
	}
}

func TestScanner_Beautify(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	scanner := newScanService(t)

	// A minified webpack-5-style bundle with several modules. Kept over the
	// ~500-byte "worth beautifying" gate so the beautify pass engages.
	bundle := []byte(`(()=>{"use strict";var e={100:(e,t,r)=>{const n=r(200);` +
		`t.listUsers=function(){return fetch(n.base+"/users",{method:"GET"}).then(x=>x.json())};` +
		`t.createUser=function(u){return fetch(n.base+"/users",{method:"POST",body:JSON.stringify(u)})};` +
		`t.deleteUser=function(id){return fetch(n.base+"/users/"+id,{method:"DELETE"})}},` +
		`200:(e,t)=>{t.base="/api/v3";t.timeout=3e4;t.retries=2;t.headers={"X-Api":"1","Accept":"application/json"}},` +
		`300:(e,t,r)=>{const n=r(200);t.listPosts=function(p){return fetch(n.base+"/posts?page="+p)};` +
		`t.render=function(items){return items&&items.map(x=>({id:x.id,title:x.title,ok:!!x.ok}))}}},t={};` +
		`function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};` +
		`return e[n](o,o.exports,r),o.exports}r.n=e=>e;var n=r(100),s=r(300);console.log(n,s)})();`)

	// Without Beautify: no beautified record.
	plain, err := scanner.Scan(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if plain.HasBeautified() {
		t.Error("did not expect a beautified record without ScanOptions.Beautify")
	}

	// With Beautify: webpack bundle unpacked into modules.
	res, err := scanner.ScanWithOptions(context.Background(), bundle, ScanOptions{Beautify: true})
	if err != nil {
		t.Fatalf("ScanWithOptions failed: %v", err)
	}
	if !res.HasBeautified() {
		t.Fatal("expected a beautified record")
	}
	b := res.Beautified
	if b.Format != "webpack" {
		t.Errorf("Format = %q, want webpack", b.Format)
	}
	if b.ModuleCount < 2 {
		t.Errorf("ModuleCount = %d, want >= 2", b.ModuleCount)
	}
	if !strings.Contains(b.Content, "fetch") {
		t.Errorf("beautified content missing expected code; got %q", b.Content)
	}
	// The content should be multi-line (unminified), unlike the single-line input.
	if strings.Count(b.Content, "\n") < 3 {
		t.Errorf("beautified content does not look unminified: %q", b.Content)
	}
}

func TestScanner_Beautify_Browserify(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}
	scanner := newScanService(t)

	bundle := []byte(`(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;` +
		`if(!f&&c)return c(i,!0);if(u)return u(i,!0);throw new Error("Cannot find module '"+i+"'")}var p=n[i]={exports:{}};` +
		`e[i][0].call(p.exports,function(r){return o(e[i][1][r]||r)},p,p.exports,r,e,n,t)}return n[i].exports}` +
		`for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()` +
		`({1:[function(require,module,exports){var api=require(2);module.exports=function(id){return api.getUser("/api/users/"+id)}},{"2":2}],` +
		`2:[function(require,module,exports){module.exports={getUser:function(url){return fetch(url,{method:"GET"})}}},{}]},{},[1]);`)

	res, err := scanner.ScanWithOptions(context.Background(), bundle, ScanOptions{Beautify: true})
	if err != nil {
		t.Fatalf("ScanWithOptions failed: %v", err)
	}
	if !res.HasBeautified() {
		t.Fatal("expected a beautified record for browserify bundle")
	}
	if res.Beautified.Format != "browserify" {
		t.Errorf("Format = %q, want browserify", res.Beautified.Format)
	}
	if res.Beautified.ModuleCount < 2 {
		t.Errorf("ModuleCount = %d, want >= 2", res.Beautified.ModuleCount)
	}
}

func TestScanner_Beautify_NonBundle(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}
	scanner := newScanService(t)

	// A long minified single line that is NOT a bundle — should unminify with
	// format "none" and zero modules.
	plain := []byte(`function a(x){return x*2}function b(y){return y+1}var c=[];for(var i=0;i<50;i++){c.push(a(i)+b(i))}` +
		`var d=c.filter(function(v){return v>10}).map(function(v){return v-1}).reduce(function(p,q){return p+q},0);` +
		`console.log(d);var e=function(t){return t?"yes":"no"};window.result=e(d>100);` +
		`var f={g:function(){return 1},h:function(){return 2},i:function(){return 3}};console.log(f.g()+f.h()+f.i());` +
		`function scale(list,factor){return list.map(function(v){return v*factor})}var g=scale(c,3);console.log(g.length);`)

	res, err := scanner.ScanWithOptions(context.Background(), plain, ScanOptions{Beautify: true})
	if err != nil {
		t.Fatalf("ScanWithOptions failed: %v", err)
	}
	if !res.HasBeautified() {
		t.Fatal("expected a beautified record for long minified script")
	}
	if res.Beautified.Format != "none" {
		t.Errorf("Format = %q, want none", res.Beautified.Format)
	}
	if res.Beautified.ModuleCount != 0 {
		t.Errorf("ModuleCount = %d, want 0", res.Beautified.ModuleCount)
	}
	if strings.Count(res.Beautified.Content, "\n") < 5 {
		t.Errorf("expected unminified multi-line content, got %q", res.Beautified.Content)
	}
}

func TestScanner_Beautify_TinyNoop(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}
	scanner := newScanService(t)

	// Below the worth-beautifying gate — no beautified record is produced.
	res, err := scanner.ScanWithOptions(context.Background(), []byte(`var api="/api/x";fetch(api);`), ScanOptions{Beautify: true})
	if err != nil {
		t.Fatalf("ScanWithOptions failed: %v", err)
	}
	if res.HasBeautified() {
		t.Error("did not expect a beautified record for a tiny script")
	}
}

func TestScanner_ContextCancellation(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	scanner := newScanService(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := scanner.Scan(ctx, []byte(`var x = 1;`))

	// The behavior depends on timing - either context.Canceled or scan completes
	// We just verify it doesn't panic
	_ = err // Error is acceptable if scan completed before cancellation
}

func TestScanner_ConcurrentScans(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	scanner := newScanService(t)

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
		t.Skip("skipping: no valid jstangle binary available")
	}

	scanner := newScanService(t)

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
		t.Skip("skipping: no valid jstangle binary available")
	}

	scanner := newScanService(t)

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
		t.Skip("skipping: no valid jstangle binary available")
	}

	scanner := newScanService(t)

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
