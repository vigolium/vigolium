package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestAuditAgentConfig_Defaults(t *testing.T) {
	cfg := config.AuditAgentConfig{}

	if cfg.IsEnabled() {
		t.Error("expected disabled by default")
	}
	if got := cfg.EffectiveMode(); got != "lite" {
		t.Errorf("expected mode 'lite', got %q", got)
	}
	if got := cfg.EffectiveSyncInterval(); got != 30 {
		t.Errorf("expected sync interval 30, got %d", got)
	}
}

func TestAuditAgentConfig_Enabled(t *testing.T) {
	enabled := true
	cfg := config.AuditAgentConfig{
		Enable: &enabled,
		Mode:   "full",
	}

	if !cfg.IsEnabled() {
		t.Error("expected enabled")
	}
	if got := cfg.EffectiveMode(); got != "full" {
		t.Errorf("expected mode 'full', got %q", got)
	}
}

func TestAuditAgentConfig_PluginDir(t *testing.T) {
	cfg := config.AuditAgentConfig{
		PluginDir: "/custom/path/to/plugin",
	}

	if got := cfg.EffectivePluginDir(); got != "/custom/path/to/plugin" {
		t.Errorf("expected custom plugin dir, got %q", got)
	}
}

func TestParseAuditFinding(t *testing.T) {
	// Create a temp finding file
	dir := t.TempDir()
	content := `# SQL Injection in User Login

## Description

The login endpoint at /api/auth/login is vulnerable to SQL injection
via the username parameter. An attacker can bypass authentication.

## Evidence

` + "```" + `
POST /api/auth/login HTTP/1.1
Content-Type: application/json

{"username": "admin' OR 1=1--", "password": "anything"}
` + "```" + `

## Remediation

Use parameterized queries instead of string concatenation.
`

	findingPath := filepath.Join(dir, "C-001.md")
	if err := os.WriteFile(findingPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	finding, err := ParseAuditFinding(findingPath)
	if err != nil {
		t.Fatal(err)
	}

	if finding.ID != "C-001" {
		t.Errorf("expected ID 'C-001', got %q", finding.ID)
	}
	if finding.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", finding.Severity)
	}
	if finding.Title != "SQL Injection in User Login" {
		t.Errorf("expected title 'SQL Injection in User Login', got %q", finding.Title)
	}
}

func TestParseAuditFinding_SeverityPrefix(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		filename string
		severity string
	}{
		{"C-001.md", "critical"},
		{"H-001.md", "high"},
		{"M-001.md", "medium"},
		{"L-001.md", "low"},
		{"I-001.md", "info"},
		{"X-001.md", "medium"}, // unknown prefix defaults to medium
	}

	for _, tt := range tests {
		path := filepath.Join(dir, tt.filename)
		if err := os.WriteFile(path, []byte("# Test Finding\n\nDescription"), 0644); err != nil {
			t.Fatal(err)
		}

		finding, err := ParseAuditFinding(path)
		if err != nil {
			t.Fatal(err)
		}

		if finding.Severity != tt.severity {
			t.Errorf("file %s: expected severity %q, got %q", tt.filename, tt.severity, finding.Severity)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"High", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"info", "info"},
		{"informational", "info"},
		{"unknown", "medium"},
		{"", "medium"},
	}

	for _, tt := range tests {
		if got := normalizeSeverity(tt.input); got != tt.expected {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSyncBuffer(t *testing.T) {
	var buf syncBuffer

	n, err := buf.Write([]byte("hello "))
	if err != nil || n != 6 {
		t.Errorf("expected 6 bytes written, got %d, err=%v", n, err)
	}

	n, err = buf.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Errorf("expected 5 bytes written, got %d, err=%v", n, err)
	}

	got := string(buf.Bytes())
	if got != "hello world" {
		t.Errorf("expected 'hello world', got %q", got)
	}
}

func TestAuditState_Parse(t *testing.T) {
	dir := t.TempDir()

	stateJSON := `{
  "audits": [
    {
      "audit_id": "2026-03-29T10:00:00Z",
      "commit": "abc123",
      "branch": "main",
      "started_at": "2026-03-29T10:00:00Z",
      "completed_at": null,
      "status": "in_progress",
      "mode": "lite",
      "phases": {
        "1": {"status": "complete", "completed_at": "2026-03-29T10:05:00Z"},
        "2": {"status": "in_progress"},
        "3": {"status": "pending"},
        "4": {"status": "pending"},
        "5": {"status": "pending"},
        "6": {"status": "pending"}
      }
    }
  ]
}`

	// Write state file to simulate source dir
	secDir := filepath.Join(dir, "security")
	if err := os.MkdirAll(secDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secDir, "audit-state.json"), []byte(stateJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a runner with the temp dir as source
	runner := &AuditAgentRunner{
		cfg:  AuditAgentConfig{SourcePath: dir},
		done: make(chan struct{}),
	}

	state := runner.readCurrentState()
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if len(state.Audits) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(state.Audits))
	}

	entry := state.Audits[0]
	if entry.Status != "in_progress" {
		t.Errorf("expected status 'in_progress', got %q", entry.Status)
	}
	if entry.Mode != "lite" {
		t.Errorf("expected mode 'lite', got %q", entry.Mode)
	}
	if len(entry.Phases) != 6 {
		t.Errorf("expected 6 phases, got %d", len(entry.Phases))
	}
	if entry.Phases["1"].Status != "complete" {
		t.Errorf("expected phase 1 complete, got %q", entry.Phases["1"].Status)
	}
}

func TestSyncStateOnce(t *testing.T) {
	sourceDir := t.TempDir()
	sessionDir := t.TempDir()

	// Write state file in source dir
	secDir := filepath.Join(sourceDir, "security")
	if err := os.MkdirAll(secDir, 0755); err != nil {
		t.Fatal(err)
	}
	stateContent := `{"audits": [{"status": "in_progress"}]}`
	if err := os.WriteFile(filepath.Join(secDir, "audit-state.json"), []byte(stateContent), 0644); err != nil {
		t.Fatal(err)
	}

	runner := &AuditAgentRunner{
		cfg:  AuditAgentConfig{SourcePath: sourceDir, SessionDir: sessionDir},
		done: make(chan struct{}),
	}

	runner.syncStateOnce()

	// Verify the state was synced to session dir
	synced, err := os.ReadFile(filepath.Join(sessionDir, "audit-agent", "audit-state.json"))
	if err != nil {
		t.Fatalf("expected synced state file, got error: %v", err)
	}
	if string(synced) != stateContent {
		t.Errorf("expected synced content %q, got %q", stateContent, string(synced))
	}
}

func TestStartAuditAgent_DisabledReturnsNil(t *testing.T) {
	cfg := config.AuditAgentConfig{} // disabled by default
	runner, err := StartAuditAgent(context.TODO(), cfg, "/some/source", "/some/session", "proj-1", "scan-1", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if runner != nil {
		t.Error("expected nil runner when disabled")
	}
}

func TestStartAuditAgent_NoSourceReturnsNil(t *testing.T) {
	enabled := true
	cfg := config.AuditAgentConfig{Enable: &enabled}
	runner, err := StartAuditAgent(context.TODO(), cfg, "", "/some/session", "proj-1", "scan-1", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if runner != nil {
		t.Error("expected nil runner when no source path")
	}
}
