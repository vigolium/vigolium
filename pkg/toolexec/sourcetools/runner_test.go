package sourcetools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestParseSemgrepOutput(t *testing.T) {
	data := []byte(`{
		"results": [
			{
				"check_id": "python.lang.security.audit.dangerous-system-call",
				"path": "app/views.py",
				"start": {"line": 42, "col": 5},
				"end": {"line": 42, "col": 30},
				"extra": {
					"message": "Detected a dangerous system call",
					"severity": "WARNING"
				}
			},
			{
				"check_id": "javascript.express.security.audit.xss.raw-html",
				"path": "src/index.js",
				"start": {"line": 10, "col": 1},
				"end": {"line": 10, "col": 50},
				"extra": {
					"message": "Raw HTML output detected",
					"severity": "HIGH"
				}
			}
		]
	}`)

	findings, err := ParseSemgrepOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// First finding
	if findings[0].RuleID != "python.lang.security.audit.dangerous-system-call" {
		t.Errorf("unexpected rule ID: %s", findings[0].RuleID)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected severity 'medium' (from WARNING), got %s", findings[0].Severity)
	}
	if findings[0].FilePath != "app/views.py" {
		t.Errorf("unexpected file path: %s", findings[0].FilePath)
	}
	if findings[0].StartLine != 42 {
		t.Errorf("expected start line 42, got %d", findings[0].StartLine)
	}
	if findings[0].ToolName != "semgrep" {
		t.Errorf("unexpected tool name: %s", findings[0].ToolName)
	}

	// Second finding
	if findings[1].Severity != "high" {
		t.Errorf("expected severity 'high', got %s", findings[1].Severity)
	}
}

func TestParseTrivyOutput(t *testing.T) {
	data := []byte(`{
		"Results": [
			{
				"Target": "package-lock.json",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2021-44228",
						"Title": "Log4Shell",
						"Description": "Remote code execution via JNDI",
						"Severity": "CRITICAL"
					}
				],
				"Misconfigurations": [
					{
						"ID": "DS001",
						"Title": "No healthcheck in Dockerfile",
						"Description": "Missing HEALTHCHECK",
						"Severity": "LOW",
						"Message": "Add HEALTHCHECK instruction"
					}
				],
				"Secrets": [
					{
						"RuleID": "aws-access-key-id",
						"Category": "AWS",
						"Title": "AWS Access Key ID",
						"Severity": "HIGH",
						"StartLine": 15,
						"EndLine": 15
					}
				]
			}
		]
	}`)

	findings, err := ParseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// Vulnerability
	if findings[0].RuleID != "CVE-2021-44228" {
		t.Errorf("unexpected vuln ID: %s", findings[0].RuleID)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("expected critical, got %s", findings[0].Severity)
	}

	// Misconfiguration
	if findings[1].RuleID != "DS001" {
		t.Errorf("unexpected misconfig ID: %s", findings[1].RuleID)
	}
	if findings[1].Severity != "low" {
		t.Errorf("expected low, got %s", findings[1].Severity)
	}

	// Secret
	if findings[2].RuleID != "aws-access-key-id" {
		t.Errorf("unexpected secret rule ID: %s", findings[2].RuleID)
	}
	if findings[2].StartLine != 15 {
		t.Errorf("expected start line 15, got %d", findings[2].StartLine)
	}
}

func TestParseSemgrepOutput_Empty(t *testing.T) {
	data := []byte(`{"results": []}`)
	findings, err := ParseSemgrepOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTrivyOutput_Empty(t *testing.T) {
	data := []byte(`{"Results": []}`)
	findings, err := ParseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseGenericJSON(t *testing.T) {
	data := []byte(`[
		{"rule_id": "R1", "message": "Something bad", "severity": "high", "file": "main.go"},
		{"id": "R2", "description": "Also bad", "level": "low", "path": "util.go"}
	]`)

	findings, err := ParseGenericJSON(data, "custom-tool")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].RuleID != "R1" {
		t.Errorf("unexpected rule ID: %s", findings[0].RuleID)
	}
	if findings[0].ToolName != "custom-tool" {
		t.Errorf("unexpected tool name: %s", findings[0].ToolName)
	}
	if findings[1].Severity != "low" {
		t.Errorf("expected low, got %s", findings[1].Severity)
	}
}

func TestParseGenericJSON_Wrapped(t *testing.T) {
	data := []byte(`{"results": [{"rule_id": "R1", "message": "Bad", "severity": "HIGH", "file": "a.go"}]}`)

	findings, err := ParseGenericJSON(data, "wrapped")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"WARNING", "medium"},
		{"LOW", "low"},
		{"INFO", "info"},
		{"NOTE", "info"},
		{"unknown", "info"},
		{"", "info"},
	}

	for _, tt := range tests {
		got := normalizeSeverity(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestToFinding(t *testing.T) {
	raw := RawFinding{
		RuleID:    "test-rule",
		Message:   "Test message",
		Severity:  "high",
		FilePath:  "src/main.go",
		StartLine: 10,
		EndLine:   15,
		ToolName:  "semgrep",
	}
	sr := &database.SourceRepo{
		ID:          1,
		ProjectUUID: database.DefaultProjectUUID,
		Hostname:    "example.com",
		Name:        "test-repo",
	}

	finding := ToFinding(raw, sr)

	if finding.ModuleID != "test-rule" {
		t.Errorf("unexpected module ID: %s", finding.ModuleID)
	}
	if finding.ModuleName != "test-rule" {
		t.Errorf("unexpected module name: %s", finding.ModuleName)
	}
	if finding.ModuleType != "sast" {
		t.Errorf("unexpected module type: %s", finding.ModuleType)
	}
	if finding.Description != "Test message" {
		t.Errorf("unexpected description: %s", finding.Description)
	}
	if finding.ModuleShort != "Test message" {
		t.Errorf("unexpected module short: %s", finding.ModuleShort)
	}
	if finding.Severity != "high" {
		t.Errorf("unexpected severity: %s", finding.Severity)
	}
	if len(finding.MatchedAt) != 1 || finding.MatchedAt[0] != "src/main.go:10-15" {
		t.Errorf("unexpected matched at: %v", finding.MatchedAt)
	}
	if len(finding.Tags) != 2 || finding.Tags[0] != "sast" || finding.Tags[1] != "semgrep" {
		t.Errorf("unexpected tags: %v", finding.Tags)
	}
	if finding.FindingHash == "" {
		t.Error("expected non-empty finding hash")
	}
	if finding.Confidence != "firm" {
		t.Errorf("unexpected confidence: %s", finding.Confidence)
	}
}

func TestFormatMatchedAt(t *testing.T) {
	tests := []struct {
		raw      RawFinding
		rootPath string
		want     string
	}{
		{RawFinding{FilePath: "a.go", StartLine: 10, EndLine: 15}, "", "a.go:10-15"},
		{RawFinding{FilePath: "a.go", StartLine: 10, EndLine: 10}, "", "a.go:10"},
		{RawFinding{FilePath: "a.go", StartLine: 10}, "", "a.go:10"},
		{RawFinding{FilePath: "a.go"}, "", "a.go"},
		{RawFinding{FilePath: "server.ts", StartLine: 281}, "/tmp/demo/juice-shop", "/tmp/demo/juice-shop/server.ts:281"},
		{RawFinding{FilePath: "src/app.js", StartLine: 10, EndLine: 15}, "/repo", "/repo/src/app.js:10-15"},
	}

	for _, tt := range tests {
		got := formatMatchedAt(tt.raw, tt.rootPath)
		if got != tt.want {
			t.Errorf("formatMatchedAt(%+v, %q) = %q, want %q", tt.raw, tt.rootPath, got, tt.want)
		}
	}
}

func testdataPath(name string) string {
	return filepath.Join("..", "..", "..", "test", "testdata", "third-party-output", name)
}

func TestParseSARIF_Semgrep(t *testing.T) {
	data, err := os.ReadFile(testdataPath("semgrep-results.sarif"))
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	findings, err := ParseSARIF(data, "semgrep")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 27 {
		t.Fatalf("expected 27 findings, got %d", len(findings))
	}

	// First finding: dockerfile.security.missing-user.missing-user
	f := findings[0]
	if f.RuleID != "dockerfile.security.missing-user.missing-user" {
		t.Errorf("unexpected rule ID: %s", f.RuleID)
	}
	if f.FilePath != "Dockerfile" {
		t.Errorf("unexpected file path: %s", f.FilePath)
	}
	if f.StartLine != 13 {
		t.Errorf("expected start line 13, got %d", f.StartLine)
	}
	// rule.defaultConfiguration.level = "error" → high
	if f.Severity != "high" {
		t.Errorf("expected severity 'high', got %s", f.Severity)
	}
	if f.ToolName != "semgrep" {
		t.Errorf("unexpected tool name: %s", f.ToolName)
	}

	// Find a warning-level rule and verify it maps to medium
	foundWarning := false
	for _, f := range findings {
		if f.Severity == "medium" {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Error("expected at least one finding with 'medium' severity (from warning-level rules)")
	}
}

func TestParseSARIF_Trivy(t *testing.T) {
	data, err := os.ReadFile(testdataPath("trivy-fs-report.sarif"))
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	findings, err := ParseSARIF(data, "trivy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// CVE-2023-30861: result.level = "error" → high
	if findings[0].RuleID != "CVE-2023-30861" {
		t.Errorf("unexpected rule ID: %s", findings[0].RuleID)
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected severity 'high' for CVE-2023-30861, got %s", findings[0].Severity)
	}

	// jwt-token: result.level = "warning" → medium
	if findings[1].RuleID != "jwt-token" {
		t.Errorf("unexpected rule ID: %s", findings[1].RuleID)
	}
	if findings[1].Severity != "medium" {
		t.Errorf("expected severity 'medium' for jwt-token, got %s", findings[1].Severity)
	}
}

func TestParseSARIF_Empty(t *testing.T) {
	// Empty runs
	data := []byte(`{"version": "2.1.0", "runs": []}`)
	findings, err := ParseSARIF(data, "tool")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}

	// Run with empty results
	data = []byte(`{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test", "rules": []}}, "results": []}]}`)
	findings, err = ParseSARIF(data, "tool")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseSARIF_SeverityResolution(t *testing.T) {
	// 1. Result level takes priority
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "test", "rules": [
				{"id": "R1", "defaultConfiguration": {"level": "note"}, "properties": {"tags": ["HIGH"]}}
			]}},
			"results": [{"ruleId": "R1", "level": "error", "message": {"text": "msg"}, "locations": []}]
		}]
	}`)
	findings, err := ParseSARIF(data, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected 'high' from result level 'error', got %s", findings[0].Severity)
	}

	// 2. Rule defaultConfiguration.level when result has no level
	data = []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "test", "rules": [
				{"id": "R1", "defaultConfiguration": {"level": "warning"}, "properties": {"tags": ["CRITICAL"]}}
			]}},
			"results": [{"ruleId": "R1", "message": {"text": "msg"}, "locations": []}]
		}]
	}`)
	findings, err = ParseSARIF(data, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected 'medium' from rule level 'warning', got %s", findings[0].Severity)
	}

	// 3. Tags fallback when no levels set
	data = []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "test", "rules": [
				{"id": "R1", "defaultConfiguration": {}, "properties": {"tags": ["security", "CRITICAL"]}}
			]}},
			"results": [{"ruleId": "R1", "message": {"text": "msg"}, "locations": []}]
		}]
	}`)
	findings, err = ParseSARIF(data, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("expected 'critical' from tags, got %s", findings[0].Severity)
	}

	// 4. Fallback to info when nothing matches
	data = []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "test", "rules": [
				{"id": "R1", "defaultConfiguration": {}, "properties": {"tags": ["security"]}}
			]}},
			"results": [{"ruleId": "R1", "message": {"text": "msg"}, "locations": []}]
		}]
	}`)
	findings, err = ParseSARIF(data, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings[0].Severity != "info" {
		t.Errorf("expected 'info' fallback, got %s", findings[0].Severity)
	}
}

func TestIsSARIF(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "SARIF with schema",
			data: `{"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}`,
			want: true,
		},
		{
			name: "SARIF without schema but with version and runs",
			data: `{"version": "2.1.0", "runs": [{"tool": {}, "results": []}]}`,
			want: true,
		},
		{
			name: "semgrep JSON",
			data: `{"results": [{"check_id": "test", "path": "a.py"}]}`,
			want: false,
		},
		{
			name: "trivy JSON",
			data: `{"Results": [{"Target": "a.go", "Vulnerabilities": []}]}`,
			want: false,
		},
		{
			name: "JSON array",
			data: `[{"id": "R1", "severity": "high"}]`,
			want: false,
		},
		{
			name: "empty object",
			data: `{}`,
			want: false,
		},
		{
			name: "empty input",
			data: ``,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSARIF([]byte(tt.data))
			if got != tt.want {
				t.Errorf("isSARIF() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseToolOutput_SARIFAutoDetect(t *testing.T) {
	data, err := os.ReadFile(testdataPath("trivy-fs-report.sarif"))
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	// parseToolOutput should auto-detect SARIF and route correctly
	findings, err := parseToolOutput("trivy", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].RuleID != "CVE-2023-30861" {
		t.Errorf("unexpected rule ID: %s", findings[0].RuleID)
	}
	if findings[0].ToolName != "trivy" {
		t.Errorf("expected tool name 'trivy', got %s", findings[0].ToolName)
	}
}

func TestParseSARIF_RuleName(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "test", "rules": [
				{"id": "R1", "shortDescription": {"text": "Short desc"}, "fullDescription": {"text": "Full desc"}, "defaultConfiguration": {"level": "error"}, "properties": {"tags": []}},
				{"id": "R2", "fullDescription": {"text": "Only full"}, "defaultConfiguration": {"level": "warning"}, "properties": {"tags": []}},
				{"id": "R3", "defaultConfiguration": {"level": "note"}, "properties": {"tags": []}}
			]}},
			"results": [
				{"ruleId": "R1", "level": "error", "message": {"text": "msg1"}, "locations": []},
				{"ruleId": "R2", "level": "warning", "message": {"text": "msg2"}, "locations": []},
				{"ruleId": "R3", "level": "note", "message": {"text": "msg3"}, "locations": []}
			]
		}]
	}`)

	findings, err := ParseSARIF(data, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// R1: shortDescription takes priority
	if findings[0].RuleName != "Short desc" {
		t.Errorf("expected RuleName 'Short desc', got %q", findings[0].RuleName)
	}
	// R2: fullDescription when no shortDescription
	if findings[1].RuleName != "Only full" {
		t.Errorf("expected RuleName 'Only full', got %q", findings[1].RuleName)
	}
	// R3: no descriptions → empty
	if findings[2].RuleName != "" {
		t.Errorf("expected empty RuleName, got %q", findings[2].RuleName)
	}
}

func TestParseSARIF_Semgrep_RuleName(t *testing.T) {
	data, err := os.ReadFile(testdataPath("semgrep-results.sarif"))
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	findings, err := ParseSARIF(data, "semgrep")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}

	// Check that at least one finding has RuleName populated
	hasRuleName := false
	for _, f := range findings {
		if f.RuleName != "" {
			hasRuleName = true
			break
		}
	}
	if !hasRuleName {
		t.Error("expected at least one finding with non-empty RuleName from semgrep SARIF")
	}
}

func TestParseSARIF_Trivy_RuleName(t *testing.T) {
	data, err := os.ReadFile(testdataPath("trivy-fs-report.sarif"))
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	findings, err := ParseSARIF(data, "trivy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}

	// First finding: CVE-2023-30861 should have shortDescription
	if findings[0].RuleName == "" {
		t.Error("expected non-empty RuleName for CVE-2023-30861")
	}
}

func TestToFinding_WithRuleName(t *testing.T) {
	raw := RawFinding{
		RuleID:    "CVE-2023-30861",
		RuleName:  "flask: Possible disclosure of permanent session cookie",
		Message:   "Specific instance message",
		Severity:  "high",
		FilePath:  "requirements.txt",
		StartLine: 5,
		ToolName:  "trivy",
	}
	sr := &database.SourceRepo{
		ID:          1,
		ProjectUUID: database.DefaultProjectUUID,
	}

	finding := ToFinding(raw, sr)

	// Description should use RuleName, not Message
	if finding.Description != "flask: Possible disclosure of permanent session cookie" {
		t.Errorf("unexpected description: %s", finding.Description)
	}
	// ModuleShort should be the per-instance message
	if finding.ModuleShort != "Specific instance message" {
		t.Errorf("unexpected module short: %s", finding.ModuleShort)
	}
}

func TestExtractSourceContext(t *testing.T) {
	// Create a temp file with 25 lines
	dir := t.TempDir()
	var lines []string
	for i := 1; i <= 25; i++ {
		lines = append(lines, fmt.Sprintf("line %d content", i))
	}
	content := strings.Join(lines, "\n") + "\n"
	err := os.WriteFile(filepath.Join(dir, "test.go"), []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Extract around line 15
	result := extractSourceContext(dir, "test.go", 15)
	if result == "" {
		t.Fatal("expected non-empty result")
	}

	// Should contain the header
	if !strings.Contains(result, "// test.go:15") {
		t.Errorf("expected header with file:line, got:\n%s", result)
	}
	// Should contain lines 5-25 (15-10=5, 15+10=25)
	if !strings.Contains(result, "line 5 content") {
		t.Errorf("expected line 5, got:\n%s", result)
	}
	if !strings.Contains(result, "line 25 content") {
		t.Errorf("expected line 25, got:\n%s", result)
	}
	// Should NOT contain line 4
	if strings.Contains(result, "line 4 content") {
		t.Errorf("should not contain line 4, got:\n%s", result)
	}
	// The matching line should have > marker
	if !strings.Contains(result, ">   15 | line 15 content") {
		t.Errorf("expected > marker on line 15, got:\n%s", result)
	}

	// Edge case: startLine near beginning
	result = extractSourceContext(dir, "test.go", 3)
	if !strings.Contains(result, "line 1 content") {
		t.Errorf("expected line 1, got:\n%s", result)
	}

	// Edge case: file doesn't exist
	result = extractSourceContext(dir, "nonexistent.go", 10)
	if result != "" {
		t.Errorf("expected empty result for nonexistent file, got: %s", result)
	}

	// Edge case: startLine = 0
	result = extractSourceContext(dir, "test.go", 0)
	if result != "" {
		t.Errorf("expected empty result for startLine=0, got: %s", result)
	}
}

func TestGroupFindings(t *testing.T) {
	raws := []RawFinding{
		{
			ToolName:  "semgrep",
			RuleID:    "xss-rule",
			RuleName:  "XSS vulnerability",
			Message:   "Found XSS",
			Severity:  "medium",
			FilePath:  "app.js",
			StartLine: 10,
		},
		{
			ToolName:  "semgrep",
			RuleID:    "xss-rule",
			RuleName:  "XSS vulnerability",
			Message:   "Found XSS",
			Severity:  "high",
			FilePath:  "app.js",
			StartLine: 25,
		},
		{
			ToolName:  "semgrep",
			RuleID:    "xss-rule",
			RuleName:  "XSS vulnerability",
			Message:   "Found XSS",
			Severity:  "low",
			FilePath:  "other.js",
			StartLine: 5,
		},
	}
	sr := &database.SourceRepo{
		ProjectUUID: database.DefaultProjectUUID,
	}

	grouped := GroupFindings(raws, sr)

	// All three share (tool, rule, desc) so they merge into one finding
	if len(grouped) != 1 {
		t.Fatalf("expected 1 grouped finding, got %d", len(grouped))
	}

	f := grouped[0]
	// All 3 locations merged
	if len(f.MatchedAt) != 3 {
		t.Errorf("expected 3 MatchedAt entries, got %d", len(f.MatchedAt))
	}
	if f.MatchedAt[0] != "app.js:10" || f.MatchedAt[1] != "app.js:25" || f.MatchedAt[2] != "other.js:5" {
		t.Errorf("unexpected MatchedAt: %v", f.MatchedAt)
	}
	// Highest severity wins across all files
	if f.Severity != "high" {
		t.Errorf("expected severity 'high', got %s", f.Severity)
	}
	if f.Description != "XSS vulnerability" {
		t.Errorf("unexpected description: %s", f.Description)
	}
}

func TestGroupFindings_DifferentRules(t *testing.T) {
	raws := []RawFinding{
		{
			ToolName:  "semgrep",
			RuleID:    "xss-rule",
			RuleName:  "XSS vulnerability",
			Message:   "Found XSS",
			Severity:  "high",
			FilePath:  "app.js",
			StartLine: 10,
		},
		{
			ToolName:  "semgrep",
			RuleID:    "sqli-rule",
			RuleName:  "SQL injection",
			Message:   "Found SQLi",
			Severity:  "critical",
			FilePath:  "app.js",
			StartLine: 20,
		},
	}
	sr := &database.SourceRepo{
		ProjectUUID: database.DefaultProjectUUID,
	}

	grouped := GroupFindings(raws, sr)

	// Different rules stay separate
	if len(grouped) != 2 {
		t.Fatalf("expected 2 grouped findings, got %d", len(grouped))
	}
}

func TestGroupFindings_Empty(t *testing.T) {
	sr := &database.SourceRepo{ProjectUUID: database.DefaultProjectUUID}
	grouped := GroupFindings(nil, sr)
	if len(grouped) != 0 {
		t.Errorf("expected 0 findings, got %d", len(grouped))
	}
	grouped = GroupFindings([]RawFinding{}, sr)
	if len(grouped) != 0 {
		t.Errorf("expected 0 findings, got %d", len(grouped))
	}
}

func TestNormalizeSARIFLevel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"error", "high"},
		{"ERROR", "high"},
		{"warning", "medium"},
		{"WARNING", "medium"},
		{"note", "low"},
		{"NOTE", "low"},
		{"none", "info"},
		{"", "info"},
		{"unknown", "info"},
	}

	for _, tt := range tests {
		got := normalizeSARIFLevel(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSARIFLevel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
