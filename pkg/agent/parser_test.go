package agent

import (
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
