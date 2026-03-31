package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateDirectoryTree(t *testing.T) {
	// Create a temp directory structure
	dir := t.TempDir()
	// Create some files and dirs
	for _, p := range []string{
		"src/main.go",
		"src/handlers/auth.go",
		"src/handlers/users.go",
		"pkg/utils/helpers.go",
		"README.md",
		"go.mod",
	} {
		full := filepath.Join(dir, p)
		if mkErr := os.MkdirAll(filepath.Dir(full), 0755); mkErr != nil {
			t.Fatal(mkErr)
		}
		if wErr := os.WriteFile(full, []byte("// "+p), 0644); wErr != nil {
			t.Fatal(wErr)
		}
	}

	// Create directories that should be skipped
	_ = os.MkdirAll(filepath.Join(dir, "node_modules", "express"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "node_modules", "express", "index.js"), []byte("//"), 0644)
	_ = os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0755)
	_ = os.WriteFile(filepath.Join(dir, ".github", "workflows", "ci.yml"), []byte("name: CI"), 0644)
	_ = os.MkdirAll(filepath.Join(dir, "coverage"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "coverage", "lcov.info"), []byte(""), 0644)
	_ = os.MkdirAll(filepath.Join(dir, "dist"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "dist", "bundle.js"), []byte(""), 0644)

	// Create files that should be filtered from the tree
	_ = os.WriteFile(filepath.Join(dir, "src", "logo.png"), []byte("PNG"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "src", "app.min.js"), []byte(""), 0644)
	_ = os.WriteFile(filepath.Join(dir, "package-lock.lock"), []byte(""), 0644)

	tree, err := generateDirectoryTree(dir)
	if err != nil {
		t.Fatalf("generateDirectoryTree() error = %v", err)
	}

	// Should contain our source dirs and files
	if !strings.Contains(tree, "src/") {
		t.Errorf("tree should contain src/, got:\n%s", tree)
	}
	if !strings.Contains(tree, "handlers/") {
		t.Errorf("tree should contain handlers/, got:\n%s", tree)
	}
	if !strings.Contains(tree, "go.mod") {
		t.Errorf("tree should contain go.mod, got:\n%s", tree)
	}

	// Should NOT contain skipped directories
	for _, skipDir := range []string{"node_modules", ".github", "coverage", "dist"} {
		if strings.Contains(tree, skipDir) {
			t.Errorf("tree should skip %s, got:\n%s", skipDir, tree)
		}
	}

	// Should NOT contain filtered files
	for _, skipFile := range []string{"logo.png", "app.min.js", "package-lock.lock"} {
		if strings.Contains(tree, skipFile) {
			t.Errorf("tree should skip %s, got:\n%s", skipFile, tree)
		}
	}
}
func TestHasVar(t *testing.T) {
	vars := []string{"TargetURL", "Hostname", "SourcePath", "DirectoryTree"}
	if !hasVar(vars, "SourcePath") {
		t.Error("expected true for SourcePath")
	}
	if hasVar(vars, "SourceCode") {
		t.Error("expected false for SourceCode")
	}
	if hasVar(nil, "anything") {
		t.Error("expected false for nil vars")
	}
}
func TestGatherContext_SkipsSourceCode(t *testing.T) {
	// When template only declares SourcePath+DirectoryTree (not SourceCode),
	// gatherContext should NOT read source files
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}"), 0644)

	e := &Engine{}
	data, err := e.gatherContext(context.Background(), Options{
		SourcePath: dir,
		TargetURL:  "http://localhost:3000",
	}, []string{"TargetURL", "SourcePath", "DirectoryTree"})

	if err != nil {
		t.Fatalf("gatherContext error: %v", err)
	}
	if data.SourceCode != "" {
		t.Errorf("expected empty SourceCode when not in templateVars, got %d bytes", len(data.SourceCode))
	}
	if data.DirectoryTree == "" {
		t.Error("expected non-empty DirectoryTree")
	}
	if data.SourcePath != dir {
		t.Errorf("SourcePath = %q, want %q", data.SourcePath, dir)
	}
}
func TestGatherContext_SkipGuidance(t *testing.T) {
	// When template declares SkipGuidance, DirectoryTree should NOT be populated
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}"), 0644)

	e := &Engine{}
	data, err := e.gatherContext(context.Background(), Options{
		SourcePath: dir,
		TargetURL:  "http://localhost:3000",
	}, []string{"TargetURL", "SourcePath", "SkipGuidance", "DirectoryTree"})

	if err != nil {
		t.Fatalf("gatherContext error: %v", err)
	}
	if data.SkipGuidance == "" {
		t.Error("expected non-empty SkipGuidance")
	}
	if data.DirectoryTree != "" {
		t.Error("expected empty DirectoryTree when SkipGuidance is declared")
	}
	if !strings.Contains(data.SkipGuidance, "Third-party") {
		t.Errorf("SkipGuidance should mention third-party libraries, got %q", data.SkipGuidance)
	}
}
func TestGatherContext_IncludesSourceCode(t *testing.T) {
	// When template declares SourceCode, files should be read
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}"), 0644)

	e := &Engine{}
	data, err := e.gatherContext(context.Background(), Options{
		SourcePath: dir,
		TargetURL:  "http://localhost:3000",
	}, []string{"TargetURL", "SourceCode", "Language"})

	if err != nil {
		t.Fatalf("gatherContext error: %v", err)
	}
	if data.SourceCode == "" {
		t.Error("expected non-empty SourceCode when declared in templateVars")
	}
	if !strings.Contains(data.SourceCode, "package main") {
		t.Errorf("SourceCode should contain file content, got %q", data.SourceCode)
	}
	if data.DirectoryTree != "" {
		t.Error("expected empty DirectoryTree when not in templateVars")
	}
}
func TestInferContentType(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"json object", `{"email":"admin@juice-sh.op","password":"admin123"}`, "application/json"},
		{"json array", `[1,2,3]`, "application/json"},
		{"xml", `<?xml version="1.0"?><root/>`, "application/xml"},
		{"soap xml", `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"></soap:Envelope>`, "application/xml"},
		{"html", `<html><body></body></html>`, "text/html"},
		{"form encoded", `email=test%40test.com&password=abc123`, "application/x-www-form-urlencoded"},
		{"plain text", `just some text`, ""},
		{"empty", ``, ""},
		{"invalid json prefix", `{not really json`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferContentType(tt.body)
			if got != tt.want {
				t.Errorf("inferContentType(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}
func TestToHTTPRequestResponse_AutoContentType(t *testing.T) {
	// POST with JSON body but no Content-Type header should auto-attach application/json
	rec := AgentHTTPRecord{
		Method: "POST",
		URL:    "http://localhost:3000/rest/user/login",
		Body:   `{"email":"admin@juice-sh.op","password":"admin123"}`,
	}

	rr, err := ToHTTPRequestResponse(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ct := rr.Request().Header("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
}
func TestToHTTPRequestResponse_ExplicitContentTypeNotOverridden(t *testing.T) {
	// When Content-Type is already set, it should NOT be overridden
	rec := AgentHTTPRecord{
		Method:  "POST",
		URL:     "http://localhost:3000/api/upload",
		Headers: map[string]string{"Content-Type": "multipart/form-data"},
		Body:    `{"this looks like json but content-type says otherwise"}`,
	}

	rr, err := ToHTTPRequestResponse(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ct := rr.Request().Header("Content-Type")
	if ct != "multipart/form-data" {
		t.Errorf("expected Content-Type 'multipart/form-data', got %q", ct)
	}
}
func TestToHTTPRequestResponse_FormEncodedBody(t *testing.T) {
	rec := AgentHTTPRecord{
		Method: "POST",
		URL:    "http://localhost:3000/login",
		Body:   "username=admin&password=admin123",
	}

	rr, err := ToHTTPRequestResponse(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ct := rr.Request().Header("Content-Type")
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("expected Content-Type 'application/x-www-form-urlencoded', got %q", ct)
	}
}
