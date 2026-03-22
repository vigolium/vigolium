package agent

import (
	"context"
	"encoding/json"
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

func TestExtractJSON_InvalidEscapes(t *testing.T) {
	// LLMs often emit regex patterns with invalid JSON escapes like \w, \d, \.
	input := "```json\n{\"findings\": [{\"title\": \"ReDoS\", \"description\": \"regex [-.\\.\\w]* and \\d+ pattern\"}]}\n```"
	result, err := extractJSON(input)
	if err != nil {
		t.Fatalf("extractJSON() error = %v", err)
	}
	// Verify the repaired JSON is parseable
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(result), &v); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	findings, ok := v["findings"].([]interface{})
	if !ok || len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %v", v["findings"])
	}
}

func TestRepairInvalidEscapes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Raw strings: \n in backticks is literal backslash+n, which is a valid JSON escape
		{"valid escapes unchanged", `{"a": "line\nbreak"}`, `{"a": "line\nbreak"}`},
		// \w is a single backslash+w (invalid JSON escape) — should become \\w (two backslashes+w)
		{"invalid \\w doubled", `{"a": "\w+"}`, `{"a": "\\w+"}`},
		{"invalid \\d doubled", `{"a": "\d"}`, `{"a": "\\d"}`},
		// \n is valid, \w is not — only \w should be doubled
		{"mixed valid and invalid", `{"a": "foo\nbar\w"}`, `{"a": "foo\nbar\\w"}`},
		{"no strings", `{"count": 42}`, `{"count": 42}`},
		// Already valid \\w (double backslash) should stay as-is
		{"already escaped", `{"a": "\\w+"}`, `{"a": "\\w+"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := repairInvalidEscapes(tt.input)
			if got != tt.want {
				t.Errorf("repairInvalidEscapes(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseFindingsWithInvalidEscapes(t *testing.T) {
	// Simulate actual LLM output with regex patterns containing invalid JSON escapes
	input := "```json\n" + `{
  "findings": [
    {
      "title": "ReDoS via Regex",
      "description": "The regex [-.\w]*[0-9a-zA-Z] is vulnerable",
      "severity": "medium",
      "confidence": "certain",
      "file": "users.py",
      "line": 145,
      "snippet": "re.search(r\"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1})$\")"
    }
  ]
}` + "\n```"

	findings, err := ParseFindings(input)
	if err != nil {
		t.Fatalf("ParseFindings() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != "ReDoS via Regex" {
		t.Errorf("unexpected title: %s", findings[0].Title)
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

func TestExtractJSONFromFencedBlock(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "json block with preamble",
			input: "Here is the analysis:\n\n```json\n{\"http_records\": [{\"method\": \"GET\", \"url\": \"http://localhost/api\"}]}\n```\n\nDone.",
			want:  `{"http_records": [{"method": "GET", "url": "http://localhost/api"}]}`,
		},
		{
			name:  "json block without preamble",
			input: "```json\n{\"key\": \"val\"}\n```",
			want:  `{"key": "val"}`,
		},
		{
			name:  "ignores javascript blocks",
			input: "```javascript\nmodule.exports = {id: \"test\"};\n```\n\n```json\n{\"http_records\": []}\n```",
			want:  `{"http_records": []}`,
		},
		{
			name:  "ignores js blocks",
			input: "```js\nvar x = {};\n```\n\n```json\n{\"result\": true}\n```",
			want:  `{"result": true}`,
		},
		{
			name:    "no json blocks",
			input:   "```javascript\nvar x = {};\n```\n\nSome text with {braces}.",
			wantErr: true,
		},
		{
			name:    "empty json block",
			input:   "```json\n\n```",
			wantErr: true,
		},
		{
			name:  "json block with whitespace",
			input: "```json\n  {\"key\": \"val\"}  \n```",
			want:  `{"key": "val"}`,
		},
		{
			name:    "jsonl is not json fence",
			input:   "```jsonl\n{\"a\":1}\n{\"b\":2}\n```",
			wantErr: true,
		},
		{
			name:  "picks first valid json block",
			input: "```json\n{\"first\": true}\n```\n\n```json\n{\"second\": true}\n```",
			want:  `{"first": true}`,
		},
		{
			name: "json block among mixed content",
			input: `Some analysis text.

#### agent-sqli.js
Reason: SQL injection found

` + "```javascript\nmodule.exports = {id: \"agent-sqli\"};\n```" + `

` + "```json\n{\"http_records\": [{\"method\": \"POST\", \"url\": \"http://localhost/login\"}], \"session_config\": {\"sessions\": []}}\n```" + `

More text here.`,
			want: `{"http_records": [{"method": "POST", "url": "http://localhost/login"}], "session_config": {"sessions": []}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractJSONFromFencedBlock(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("extractJSONFromFencedBlock() expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractJSONFromFencedBlock() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("extractJSONFromFencedBlock() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractJSONLFromFencedBlock(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "valid jsonl block",
			input: "Here are the routes:\n\n```jsonl\n{\"method\":\"GET\",\"url\":\"http://localhost/api\"}\n{\"method\":\"POST\",\"url\":\"http://localhost/login\"}\n```\n\nDone.",
			want:  "{\"method\":\"GET\",\"url\":\"http://localhost/api\"}\n{\"method\":\"POST\",\"url\":\"http://localhost/login\"}",
		},
		{
			name:  "jsonl block with extra whitespace",
			input: "```jsonl\n  {\"method\":\"GET\",\"url\":\"http://localhost/a\"}  \n```",
			want:  "{\"method\":\"GET\",\"url\":\"http://localhost/a\"}",
		},
		{
			name:    "no jsonl block",
			input:   "```json\n{\"key\":\"val\"}\n```",
			wantErr: true,
		},
		{
			name:    "empty jsonl block",
			input:   "```jsonl\n\n```",
			wantErr: true,
		},
		{
			name:    "jsonlines is not jsonl",
			input:   "```jsonlines\n{\"a\":1}\n```",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractJSONLFromFencedBlock(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseHTTPRecordJSONL_ValidLines(t *testing.T) {
	input := `{"method":"GET","url":"http://localhost/api/users","headers":{},"notes":"List users"}
{"method":"POST","url":"http://localhost/api/login","headers":{"Content-Type":"application/json"},"body":"{\"user\":\"admin\"}","notes":"Login"}`

	records, badCount := parseHTTPRecordJSONL(input)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if badCount != 0 {
		t.Errorf("expected 0 bad lines, got %d", badCount)
	}
	if records[0].Method != "GET" {
		t.Errorf("first record method = %q, want GET", records[0].Method)
	}
	if records[1].URL != "http://localhost/api/login" {
		t.Errorf("second record url = %q", records[1].URL)
	}
}

func TestParseHTTPRecordJSONL_SkipBadLines(t *testing.T) {
	input := `{"method":"GET","url":"http://localhost/api/good","headers":{}}
{"method":"GET","url":"broken json
{"method":"POST","url":"http://localhost/api/also-good","headers":{"Content-Type":"application/json"},"body":"{}"}
not json at all
{"method":"INVALID_METHOD","url":"http://localhost/bad"}`

	records, badCount := parseHTTPRecordJSONL(input)
	// INVALID_METHOD is now inferred as GET, so 3 good records, 2 bad lines
	if len(records) != 3 {
		t.Fatalf("expected 3 good records (INVALID_METHOD inferred as GET), got %d", len(records))
	}
	if badCount != 2 {
		t.Errorf("expected 2 bad lines, got %d", badCount)
	}
}

func TestParseHTTPRecordJSONL_AllBad(t *testing.T) {
	input := `not json
also not json
{"method":"FAKEVERB","url":""}`

	records, badCount := parseHTTPRecordJSONL(input)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
	if badCount != 3 {
		t.Errorf("expected 3 bad lines, got %d", badCount)
	}
}

func TestParseHTTPRecordJSONL_SkipsComments(t *testing.T) {
	input := `// This is a comment
# Another comment
{"method":"GET","url":"http://localhost/api","headers":{}}

`
	records, badCount := parseHTTPRecordJSONL(input)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if badCount != 0 {
		t.Errorf("expected 0 bad lines, got %d", badCount)
	}
}

func TestExtractRecordsFromGarbled(t *testing.T) {
	// Simulate a garbled JSON array where one field is corrupted
	input := `[{"method":"GET","url":"http://localhost/api/users","headers":{},"notes":"List users"},{"method":"POST","url":"http://localhost/api/login","headers":{"Content-Type":"application/json"},"body":"{\"email\":\"test@test.com\","password":"broken_here"},"notes":"Login"},{"method":"DELETE","url":"http://localhost/api/users/1","headers":{},"notes":"Delete user"}]`

	records, failCount := extractRecordsFromGarbled(input)
	// Should recover at least the valid records
	if len(records) < 2 {
		t.Errorf("expected at least 2 recovered records, got %d (failed: %d)", len(records), failCount)
	}
	// Check that recovered records have valid methods
	for _, rec := range records {
		if !validHTTPMethods[rec.Method] {
			t.Errorf("recovered record has invalid method: %q", rec.Method)
		}
	}
}

func TestExtractRecordsFromGarbledCleanArray(t *testing.T) {
	// Clean array should recover all records
	input := `[{"method":"GET","url":"http://localhost/a","headers":{}},{"method":"POST","url":"http://localhost/b","headers":{}}]`
	records, failCount := extractRecordsFromGarbled(input)
	if len(records) != 2 {
		t.Errorf("expected 2 records, got %d (failed: %d)", len(records), failCount)
	}
}

func TestIsValidHTTPRecord(t *testing.T) {
	tests := []struct {
		name  string
		rec   AgentHTTPRecord
		valid bool
	}{
		{"valid GET", AgentHTTPRecord{Method: "GET", URL: "http://localhost/api"}, true},
		{"valid POST", AgentHTTPRecord{Method: "POST", URL: "https://example.com/login"}, true},
		{"valid lowercase method", AgentHTTPRecord{Method: "get", URL: "http://localhost/api"}, true}, // case-insensitive
		{"empty method", AgentHTTPRecord{Method: "", URL: "http://localhost/api"}, false},
		{"invalid method", AgentHTTPRecord{Method: "FOOBAR", URL: "http://localhost/api"}, false},
		{"empty url", AgentHTTPRecord{Method: "GET", URL: ""}, false},
		{"no scheme", AgentHTTPRecord{Method: "GET", URL: "localhost/api"}, false},
		{"relative path", AgentHTTPRecord{Method: "GET", URL: "/api/users"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHTTPRecord(tt.rec)
			if got != tt.valid {
				t.Errorf("isValidHTTPRecord(%+v) = %v, want %v", tt.rec, got, tt.valid)
			}
		})
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

func TestNormalizeAgentRecords(t *testing.T) {
	records := []AgentHTTPRecord{
		// Valid record — should pass through
		{Method: "GET", URL: "http://localhost:3000/api/products", Headers: map[string]string{}},
		// POST with JSON body but no Content-Type — should auto-detect
		{Method: "POST", URL: "http://localhost:3000/rest/user/login", Body: `{"email":"admin@juice-sh.op","password":"admin123"}`},
		// Garbled URL — non-ASCII chars
		{Method: "GET", URL: "http://localhost:3000/api\x00/bad"},
		// Empty URL — should be dropped
		{Method: "GET", URL: ""},
		// Invalid method, no body — inferred as GET (not dropped)
		{Method: "INVALID", URL: "http://localhost:3000/api"},
		// Double slash in path — should be fixed
		{Method: "GET", URL: "http://localhost:3000//api//products"},
	}

	normalized, dropped := NormalizeAgentRecords(records)

	// Only empty URL should be dropped; invalid method is now inferred
	if dropped != 1 {
		t.Errorf("expected 1 dropped, got %d", dropped)
	}
	if len(normalized) != 5 {
		t.Fatalf("expected 5 normalized records, got %d", len(normalized))
	}

	// Check double slash is fixed
	for _, rec := range normalized {
		if strings.Contains(rec.URL, "//api//") {
			t.Errorf("expected double slashes to be fixed in URL: %s", rec.URL)
		}
	}

	// Check that the previously-invalid method was inferred as GET
	for _, rec := range normalized {
		if rec.URL == "http://localhost:3000/api" && rec.Method != "GET" {
			t.Errorf("expected inferred method GET for formerly-INVALID record, got %q", rec.Method)
		}
	}
}

func TestNormalizeBody_TruncatedJSON(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		isValid bool // whether result should be valid JSON
	}{
		{"complete json", `{"key":"value"}`, true},
		{"truncated object", `{"key":"value","nested":{"a":"b"`, true},
		{"truncated array", `[1,2,{"key":"val"`, true},
		{"truncated string", `{"key":"val`, true},
		{"not json", `just text`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeBody(tt.body)
			if tt.isValid && !isJSON(result) {
				t.Errorf("normalizeBody(%q) = %q, expected valid JSON", tt.body, result)
			}
		})
	}
}

func TestIsValidHeaderName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"normal header", "Content-Type", true},
		{"x-custom", "X-Custom-Header", true},
		{"authorization", "Authorization", true},
		{"empty", "", false},
		{"with space", "Content Type", false},
		{"with colon", "Host:", false},
		{"non-ascii", "Héader", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHeaderName(tt.input)
			if got != tt.want {
				t.Errorf("isValidHeaderName(%q) = %v, want %v", tt.input, got, tt.want)
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

func TestParseHTTPRecordJSONL_TrailingGarbage(t *testing.T) {
	// Line has valid JSON followed by trailing garbage text
	input := `{"method":"GET","url":"http://localhost:3000/api/products","headers":{}} accounting for rate limits`

	records, badCount := parseHTTPRecordJSONL(input)
	if len(records) != 1 {
		t.Fatalf("expected 1 record recovered from trailing garbage, got %d (bad: %d)", len(records), badCount)
	}
	if records[0].Method != "GET" {
		t.Errorf("method = %q, want GET", records[0].Method)
	}
	if records[0].URL != "http://localhost:3000/api/products" {
		t.Errorf("url = %q", records[0].URL)
	}
}

func TestParseHTTPRecordJSONL_InvalidMethodNormalized(t *testing.T) {
	// Method field contains garbage (path fragment), but record has a body → infer POST
	input := `{"method":"3000/profile/image/file","url":"http://localhost:3000/api/upload","headers":{"Content-Type":"application/json"},"body":"{\"file\":\"test.png\"}"}`

	records, badCount := parseHTTPRecordJSONL(input)
	if len(records) != 1 {
		t.Fatalf("expected 1 record with inferred method, got %d (bad: %d)", len(records), badCount)
	}
	if records[0].Method != "POST" {
		t.Errorf("expected inferred method POST, got %q", records[0].Method)
	}
}

func TestCleanAgentURL_EmbeddedURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"embedded http in path",
			"/order-history/http://localhost:3000/rest/products",
			"http://localhost:3000/rest/products",
		},
		{
			"embedded https in path",
			"/prefix/https://example.com/api/v2",
			"https://example.com/api/v2",
		},
		{
			"no embedded URL",
			"http://localhost:3000/api/users",
			"http://localhost:3000/api/users",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanAgentURL(tt.input)
			if got != tt.want {
				t.Errorf("cleanAgentURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeRecord_MethodInference(t *testing.T) {
	tests := []struct {
		name       string
		rec        AgentHTTPRecord
		wantMethod string
		wantOK     bool
	}{
		{
			"garbage method with body → POST",
			AgentHTTPRecord{Method: "3000/profile/image/file", URL: "http://localhost:3000/api", Body: `{"key":"val"}`},
			"POST",
			true,
		},
		{
			"garbage method no body → GET",
			AgentHTTPRecord{Method: "FAKEVERB", URL: "http://localhost:3000/api"},
			"GET",
			true,
		},
		{
			"valid method unchanged",
			AgentHTTPRecord{Method: "DELETE", URL: "http://localhost:3000/api/users/1"},
			"DELETE",
			true,
		},
		{
			"empty URL still fails",
			AgentHTTPRecord{Method: "GET", URL: ""},
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeRecord(tt.rec)
			if ok != tt.wantOK {
				t.Fatalf("normalizeRecord() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got.Method != tt.wantMethod {
				t.Errorf("method = %q, want %q", got.Method, tt.wantMethod)
			}
		})
	}
}

func TestAgentHTTPRecord_UnmarshalJSON_BodyAsString(t *testing.T) {
	// Normal case: body is a properly escaped JSON string
	input := `{"method":"POST","url":"http://localhost/api","body":"{\"email\":\"a@b.com\"}"}`
	var rec AgentHTTPRecord
	if err := json.Unmarshal([]byte(input), &rec); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if rec.Body != `{"email":"a@b.com"}` {
		t.Errorf("body = %q, want %q", rec.Body, `{"email":"a@b.com"}`)
	}
}

func TestAgentHTTPRecord_UnmarshalJSON_BodyAsObject(t *testing.T) {
	// LLM mistake: body is a raw JSON object instead of an escaped string
	input := `{"method":"POST","url":"http://localhost/api","body":{"email":"a@b.com","password":"test123"}}`
	var rec AgentHTTPRecord
	if err := json.Unmarshal([]byte(input), &rec); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if rec.Method != "POST" {
		t.Errorf("method = %q, want POST", rec.Method)
	}
	// Body should be re-serialized as a JSON string
	if !isJSON(rec.Body) {
		t.Errorf("body should be valid JSON, got %q", rec.Body)
	}
	if !strings.Contains(rec.Body, `"email"`) || !strings.Contains(rec.Body, `"password"`) {
		t.Errorf("body should contain email and password fields, got %q", rec.Body)
	}
}

func TestAgentHTTPRecord_UnmarshalJSON_BodyAsArray(t *testing.T) {
	// LLM mistake: body is a JSON array
	input := `{"method":"POST","url":"http://localhost/api","body":[{"id":1},{"id":2}]}`
	var rec AgentHTTPRecord
	if err := json.Unmarshal([]byte(input), &rec); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if !isJSON(rec.Body) {
		t.Errorf("body should be valid JSON, got %q", rec.Body)
	}
	if !strings.Contains(rec.Body, `[`) {
		t.Errorf("body should contain array, got %q", rec.Body)
	}
}

func TestAgentHTTPRecord_UnmarshalJSON_BodyEmpty(t *testing.T) {
	input := `{"method":"GET","url":"http://localhost/api"}`
	var rec AgentHTTPRecord
	if err := json.Unmarshal([]byte(input), &rec); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if rec.Body != "" {
		t.Errorf("body = %q, want empty", rec.Body)
	}
}

func TestAgentHTTPRecord_UnmarshalJSON_BodyAsNumber(t *testing.T) {
	// Edge case: body is a bare number (should be kept as-is)
	input := `{"method":"POST","url":"http://localhost/api","body":42}`
	var rec AgentHTTPRecord
	if err := json.Unmarshal([]byte(input), &rec); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if rec.Body != "42" {
		t.Errorf("body = %q, want %q", rec.Body, "42")
	}
}

func TestParseHTTPRecordJSONL_BodyAsObject(t *testing.T) {
	// JSONL where one line has body as object instead of string — should be recovered
	input := `{"method":"GET","url":"http://localhost/api/users","headers":{}}
{"method":"POST","url":"http://localhost/api/login","headers":{"Content-Type":"application/json"},"body":{"email":"admin@test.com","password":"admin123"},"notes":"Login"}
{"method":"PUT","url":"http://localhost/api/users/1","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"updated\"}"}`

	records, badCount := parseHTTPRecordJSONL(input)
	if len(records) != 3 {
		t.Fatalf("expected 3 records (body-as-object should be recovered), got %d (bad: %d)", len(records), badCount)
	}
	if badCount != 0 {
		t.Errorf("expected 0 bad lines, got %d", badCount)
	}
	// The body-as-object record should have its body re-serialized as a JSON string
	if !isJSON(records[1].Body) {
		t.Errorf("record[1].body should be valid JSON, got %q", records[1].Body)
	}
	if !strings.Contains(records[1].Body, "admin@test.com") {
		t.Errorf("record[1].body should contain email, got %q", records[1].Body)
	}
}
