package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractJSON_Clean(t *testing.T) {
	input := `{"findings": [{"title": "XSS", "severity": "high"}]}`
	result, err := extractJSON(input)
	if err != nil {
		t.Fatalf("extractJSON() error = %v", err)
	}
	if result != input {
		t.Errorf("expected clean passthrough, got %q", result)
	}
}

func TestExtractJSON_MarkdownFences(t *testing.T) {
	input := "```json\n{\"findings\": []}\n```"
	result, err := extractJSON(input)
	if err != nil {
		t.Fatalf("extractJSON() error = %v", err)
	}
	if result != `{"findings": []}` {
		t.Errorf("expected stripped JSON, got %q", result)
	}
}

func TestExtractJSON_Preamble(t *testing.T) {
	input := "Here are the findings:\n\n{\"findings\": [{\"title\": \"test\"}]}"
	result, err := extractJSON(input)
	if err != nil {
		t.Fatalf("extractJSON() error = %v", err)
	}
	if result != `{"findings": [{"title": "test"}]}` {
		t.Errorf("expected extracted JSON, got %q", result)
	}
}

func TestExtractJSON_Invalid(t *testing.T) {
	_, err := extractJSON("this is not json at all")
	if err == nil {
		t.Error("expected error for non-JSON input")
	}
}

func TestExtractJSON_Array(t *testing.T) {
	input := `[{"title": "test"}]`
	result, err := extractJSON(input)
	if err != nil {
		t.Fatalf("extractJSON() error = %v", err)
	}
	if result != input {
		t.Errorf("expected array passthrough, got %q", result)
	}
}

func TestParseFindings(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid findings object",
			input:   `{"findings": [{"title": "XSS", "severity": "high", "file": "app.js", "line": 10}]}`,
			wantLen: 1,
		},
		{
			name:    "bare array",
			input:   `[{"title": "SQLi", "severity": "critical"}]`,
			wantLen: 1,
		},
		{
			name:    "empty findings",
			input:   `{"findings": []}`,
			wantLen: 0,
			wantErr: true, // empty findings parsed but len=0 triggers struct parse, then array parse also gives 0
		},
		{
			name:    "with markdown fences",
			input:   "```json\n{\"findings\": [{\"title\": \"SSRF\", \"severity\": \"high\"}]}\n```",
			wantLen: 1,
		},
		{
			name:    "invalid json",
			input:   "not json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := ParseFindings(tt.input)
			if tt.wantErr {
				if err == nil && len(findings) != 0 {
					t.Errorf("ParseFindings() expected error or empty result")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFindings() error = %v", err)
			}
			if len(findings) != tt.wantLen {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantLen)
			}
		})
	}
}

func TestParseHTTPRecords(t *testing.T) {
	input := `{"http_records": [{"method": "GET", "url": "https://example.com/api/users", "notes": "List users"}]}`
	records, err := ParseHTTPRecords(input)
	if err != nil {
		t.Fatalf("ParseHTTPRecords() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Method != "GET" {
		t.Errorf("method = %q, want GET", records[0].Method)
	}
	if records[0].URL != "https://example.com/api/users" {
		t.Errorf("url = %q, want https://example.com/api/users", records[0].URL)
	}
}

func TestToDBFinding(t *testing.T) {
	af := AgentFinding{
		Title:       "SQL Injection in login",
		Description: "User input flows into SQL query",
		Severity:    "critical",
		Confidence:  "firm",
		File:        "auth/login.go",
		Line:        42,
		Snippet:     "db.Query(\"SELECT * FROM users WHERE id = \" + id)",
		CWE:         "CWE-89",
		Tags:        []string{"sqli"},
	}

	finding := ToDBFinding(af, "agent-security-code-review", "scan-123", "")

	if finding.ModuleID != "agent-security-code-review" {
		t.Errorf("ModuleID = %q, want %q", finding.ModuleID, "agent-security-code-review")
	}
	if finding.ModuleName != "SQL Injection in login" {
		t.Errorf("ModuleName = %q, want %q", finding.ModuleName, "SQL Injection in login")
	}
	if finding.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", finding.Severity, "critical")
	}
	if finding.Confidence != "firm" {
		t.Errorf("Confidence = %q, want %q", finding.Confidence, "firm")
	}
	if finding.ScanUUID != "scan-123" {
		t.Errorf("ScanUUID = %q, want %q", finding.ScanUUID, "scan-123")
	}
	if len(finding.MatchedAt) != 1 || finding.MatchedAt[0] != "auth/login.go:42" {
		t.Errorf("MatchedAt = %v, want [auth/login.go:42]", finding.MatchedAt)
	}
	if finding.FindingHash == "" {
		t.Error("FindingHash should not be empty")
	}
	// Tags should include the original tag plus the CWE
	if len(finding.Tags) != 2 {
		t.Errorf("Tags = %v, want 2 items", finding.Tags)
	}
}

func TestToDBFinding_Defaults(t *testing.T) {
	af := AgentFinding{
		Title: "Something suspicious",
	}

	finding := ToDBFinding(af, "agent-test", "", "")

	if finding.Severity != "info" {
		t.Errorf("Severity should default to 'info', got %q", finding.Severity)
	}
	if finding.Confidence != "tentative" {
		t.Errorf("Confidence should default to 'tentative', got %q", finding.Confidence)
	}
}

func TestFindAllJSONBlocks(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		count  int
		first  string
	}{
		{
			name:  "single object",
			input: `some text {"key": "val"} more text`,
			count: 1,
			first: `{"key": "val"}`,
		},
		{
			name:  "multiple blocks",
			input: `{"a":1} text {"b":2} more [3,4]`,
			count: 3,
			first: `{"a":1}`,
		},
		{
			name:  "corrupted first then valid second",
			input: `{"broken": "no closing brace {"module_tags":["xss"]}`,
			count: 1,
			first: `{"module_tags":["xss"]}`,
		},
		{
			name:  "nested braces",
			input: `{"outer":{"inner":"val"}} done`,
			count: 1,
			first: `{"outer":{"inner":"val"}}`,
		},
		{
			name:  "no blocks",
			input: "no json here at all",
			count: 0,
		},
		{
			name:  "array block",
			input: `prefix [{"a":1},{"b":2}] suffix`,
			count: 1,
			first: `[{"a":1},{"b":2}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks := findAllJSONBlocks(tt.input)
			if len(blocks) != tt.count {
				t.Fatalf("expected %d blocks, got %d: %v", tt.count, len(blocks), blocks)
			}
			if tt.count > 0 && blocks[0] != tt.first {
				t.Errorf("first block = %q, want %q", blocks[0], tt.first)
			}
		})
	}
}

func TestExtractJSON_InnerFencedBlock(t *testing.T) {
	// JSON is inside a markdown fence in the middle of other text
	input := "Here is the plan:\n\n```json\n{\"module_tags\": [\"xss\"]}\n```\n\nDone."
	result, err := extractJSON(input)
	if err != nil {
		t.Fatalf("extractJSON() error = %v", err)
	}
	if result != `{"module_tags": ["xss"]}` {
		t.Errorf("expected JSON from fenced block, got %q", result)
	}
}

func TestExtractJSON_GarbledReportsSpecificError(t *testing.T) {
	// Garbled JSON: balanced braces but invalid content
	input := `{"key": "val",, "broken": }`
	_, err := extractJSON(input)
	if err == nil {
		t.Fatal("expected error for garbled JSON")
	}
	if !strings.Contains(err.Error(), "syntax errors") {
		t.Errorf("expected error to mention syntax errors, got: %v", err)
	}
	if !strings.Contains(err.Error(), "snippet:") {
		t.Errorf("expected error to include snippet, got: %v", err)
	}
}

func TestExtractJSON_CorruptedFirstValidSecond(t *testing.T) {
	// First JSON block is corrupted (unbalanced), second is valid
	input := `Here is the plan: {"broken": "missing close brace
And here is the real one: {"module_tags": ["xss", "sqli"]}`
	result, err := extractJSON(input)
	if err != nil {
		t.Fatalf("extractJSON() error = %v", err)
	}
	if result != `{"module_tags": ["xss", "sqli"]}` {
		t.Errorf("expected valid second block, got %q", result)
	}
}

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

	// Also create node_modules (should be skipped)
	os.MkdirAll(filepath.Join(dir, "node_modules", "express"), 0755)
	os.WriteFile(filepath.Join(dir, "node_modules", "express", "index.js"), []byte("//"), 0644)

	tree, err := generateDirectoryTree(dir)
	if err != nil {
		t.Fatalf("generateDirectoryTree() error = %v", err)
	}

	// Should contain our source dirs
	if !strings.Contains(tree, "src/") {
		t.Errorf("tree should contain src/, got:\n%s", tree)
	}
	if !strings.Contains(tree, "handlers/") {
		t.Errorf("tree should contain handlers/, got:\n%s", tree)
	}
	if !strings.Contains(tree, "go.mod") {
		t.Errorf("tree should contain go.mod, got:\n%s", tree)
	}
	// Should NOT contain node_modules
	if strings.Contains(tree, "node_modules") {
		t.Errorf("tree should skip node_modules, got:\n%s", tree)
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
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}"), 0644)

	e := &Engine{}
	data, err := e.gatherContext(Options{
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

func TestGatherContext_IncludesSourceCode(t *testing.T) {
	// When template declares SourceCode, files should be read
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}"), 0644)

	e := &Engine{}
	data, err := e.gatherContext(Options{
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

func TestStripMarkdownFences(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"```json\n{\"key\": \"val\"}\n```", `{"key": "val"}`},
		{"```\n{\"key\": \"val\"}\n```", `{"key": "val"}`},
		{`{"key": "val"}`, `{"key": "val"}`},
		{"no fences", "no fences"},
	}

	for _, tt := range tests {
		got := stripMarkdownFences(tt.input)
		if got != tt.want {
			t.Errorf("stripMarkdownFences(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
