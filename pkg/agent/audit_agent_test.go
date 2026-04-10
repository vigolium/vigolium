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
	if got := cfg.EffectivePlatform(); got != "claude" {
		t.Errorf("expected platform 'claude', got %q", got)
	}
	if got := cfg.EffectiveSyncInterval(); got != 30 {
		t.Errorf("expected sync interval 30, got %d", got)
	}
}

func TestAuditAgentConfig_Enabled(t *testing.T) {
	enabled := true
	cfg := config.AuditAgentConfig{
		Enable: &enabled,
		Mode:   "deep",
	}

	if !cfg.IsEnabled() {
		t.Error("expected enabled")
	}
	if got := cfg.EffectiveMode(); got != "deep" {
		t.Errorf("expected mode 'deep', got %q", got)
	}
}

func TestAuditAgentConfig_LegacyFullMode(t *testing.T) {
	cfg := config.AuditAgentConfig{Mode: "full"}
	if got := cfg.EffectiveMode(); got != "deep" {
		t.Errorf("expected legacy 'full' to map to 'deep', got %q", got)
	}
}

func TestAuditAgentConfig_ScanMode(t *testing.T) {
	cfg := config.AuditAgentConfig{Mode: "scan"}
	if got := cfg.EffectiveMode(); got != "scan" {
		t.Errorf("expected mode 'scan', got %q", got)
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
      "completed_at": "2026-03-29T10:30:00Z",
      "status": "in_progress",
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

	// Write state file to simulate archon/ dir in source
	archonDir := filepath.Join(dir, "archon")
	if err := os.MkdirAll(archonDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archonDir, "audit-state.json"), []byte(stateJSON), 0644); err != nil {
		t.Fatal(err)
	}

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
	if len(entry.Phases) != 6 {
		t.Errorf("expected 6 phases, got %d", len(entry.Phases))
	}
}

func TestSyncStateOnce(t *testing.T) {
	sourceDir := t.TempDir()
	sessionDir := t.TempDir()

	// Write state file in source archon/ dir
	archonDir := filepath.Join(sourceDir, "archon")
	if err := os.MkdirAll(archonDir, 0755); err != nil {
		t.Fatal(err)
	}
	stateContent := `{"audits": [{"status": "in_progress"}]}`
	if err := os.WriteFile(filepath.Join(archonDir, "audit-state.json"), []byte(stateContent), 0644); err != nil {
		t.Fatal(err)
	}

	runner := &AuditAgentRunner{
		cfg:  AuditAgentConfig{SourcePath: sourceDir, SessionDir: sessionDir},
		done: make(chan struct{}),
	}

	runner.syncStateOnce()

	// Verify the state was synced to session dir
	synced, err := os.ReadFile(filepath.Join(sessionDir, "archon-audit", "audit-state.json"))
	if err != nil {
		t.Fatalf("expected synced state file, got error: %v", err)
	}
	if string(synced) != stateContent {
		t.Errorf("expected synced content %q, got %q", stateContent, string(synced))
	}
}

func TestCopyDir(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	// Create test structure
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file1.md"), []byte("content1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "file2.md"), []byte("content2"), 0644); err != nil {
		t.Fatal(err)
	}

	copyDir(srcDir, destDir)

	// Verify
	data1, err := os.ReadFile(filepath.Join(destDir, "file1.md"))
	if err != nil {
		t.Fatalf("expected file1.md, got error: %v", err)
	}
	if string(data1) != "content1" {
		t.Errorf("expected 'content1', got %q", string(data1))
	}
	data2, err := os.ReadFile(filepath.Join(destDir, "sub", "file2.md"))
	if err != nil {
		t.Fatalf("expected sub/file2.md, got error: %v", err)
	}
	if string(data2) != "content2" {
		t.Errorf("expected 'content2', got %q", string(data2))
	}
}

func TestStartAuditAgent_DisabledReturnsNil(t *testing.T) {
	cfg := config.AuditAgentConfig{} // disabled by default
	runner, err := StartAuditAgent(context.TODO(), cfg, "/some/source", "/some/session", "proj-1", "scan-1", "", nil, nil)
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
	runner, err := StartAuditAgent(context.TODO(), cfg, "", "/some/session", "proj-1", "scan-1", "", nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if runner != nil {
		t.Error("expected nil runner when no source path")
	}
}

func TestAuditAgentConfig_Platform(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "claude"},
		{"claude", "claude"},
		{"codex", "codex"},
		{"opencode", "opencode"},
		{"unknown", "claude"},
	}

	for _, tt := range tests {
		cfg := config.AuditAgentConfig{Platform: tt.input}
		if got := cfg.EffectivePlatform(); got != tt.expected {
			t.Errorf("Platform(%q): expected %q, got %q", tt.input, tt.expected, got)
		}
	}
}

func TestBuildAuditAgentCommand_Claude(t *testing.T) {
	// This test only verifies the args structure, not that the binary exists.
	// We skip if claude is not in PATH.
	binary, args, stdinPrompt, err := buildAuditAgentCommand("claude", "/tmp/plugin", "deep", "/tmp/source", false)
	if err != nil {
		t.Skipf("claude not in PATH: %v", err)
	}
	if binary == "" {
		t.Error("expected non-empty binary")
	}
	// Check key args are present
	foundPlugin := false
	foundAllowed := false
	for _, a := range args {
		if a == "--plugin-dir" {
			foundPlugin = true
		}
		if a == "--allowedTools" {
			foundAllowed = true
		}
	}
	if !foundPlugin {
		t.Error("expected --plugin-dir in claude args")
	}
	if !foundAllowed {
		t.Error("expected --allowedTools in claude args")
	}
	// Skill command should be the last positional arg (not piped via stdin)
	lastArg := args[len(args)-1]
	if lastArg != "/archon-audit:archon:deep" {
		t.Errorf("expected last arg = /archon-audit:archon:deep, got %q", lastArg)
	}
	if stdinPrompt != "" {
		t.Errorf("expected empty stdinPrompt, got %q", stdinPrompt)
	}
}

func TestBuildAuditAgentCommand_ClaudeStream(t *testing.T) {
	_, args, _, err := buildAuditAgentCommand("claude", "/tmp/plugin", "deep", "/tmp/source", true)
	if err != nil {
		t.Skipf("claude not in PATH: %v", err)
	}
	// Stream mode must emit stream-json + --verbose + --include-partial-messages.
	want := map[string]bool{
		"--output-format":           false,
		"stream-json":               false,
		"--verbose":                 false,
		"--include-partial-messages": false,
	}
	for _, a := range args {
		if _, ok := want[a]; ok {
			want[a] = true
		}
	}
	for flag, seen := range want {
		if !seen {
			t.Errorf("stream mode missing expected arg %q in %v", flag, args)
		}
	}
	// Slash command still last.
	if args[len(args)-1] != "/archon-audit:archon:deep" {
		t.Errorf("expected last arg = /archon-audit:archon:deep, got %q", args[len(args)-1])
	}
}

func TestBuildAuditAgentCommand_Codex(t *testing.T) {
	binary, args, _, err := buildAuditAgentCommand("codex", "/tmp/plugin", "lite", "/tmp/source", false)
	if err != nil {
		t.Skipf("codex not in PATH: %v", err)
	}
	if binary == "" {
		t.Error("expected non-empty binary")
	}
	found := false
	for _, a := range args {
		if a == "--full-auto" {
			found = true
		}
	}
	if !found {
		t.Error("expected --full-auto in codex args")
	}
}

func TestBuildAuditAgentCommand_OpenCode(t *testing.T) {
	binary, args, _, err := buildAuditAgentCommand("opencode", "/tmp/plugin", "scan", "/tmp/source", false)
	if err != nil {
		t.Skipf("opencode not in PATH: %v", err)
	}
	if binary == "" {
		t.Error("expected non-empty binary")
	}
	found := false
	for _, a := range args {
		if a == "--agents-dir" {
			found = true
		}
	}
	if !found {
		t.Error("expected --agents-dir in opencode args")
	}
}

func TestResolveAuditAgentConfig_PreservesPlatform(t *testing.T) {
	base := config.AuditAgentConfig{Platform: "codex"}
	result := ResolveAuditAgentConfig(false, "deep", "/some/source", base)
	if result == nil {
		t.Fatal("expected non-nil config")
	}
	if result.Platform != "codex" {
		t.Errorf("expected platform 'codex' to be preserved, got %q", result.Platform)
	}
}

// TestReadCurrentState_SessionDirFallback verifies that Status() can recover
// the audit state after monitor() has removed SourcePath/archon/ — the CLI
// summary is the primary consumer and runs after cleanup.
func TestReadCurrentState_SessionDirFallback(t *testing.T) {
	sourceDir := t.TempDir()
	sessionDir := t.TempDir()

	// Only write the state file into the session dir, not the source dir.
	state := `{"audits":[{"audit_id":"t1","status":"complete","phases":{"Q0":{"status":"complete"},"Q1":{"status":"complete"},"Q2":{"status":"complete"}}}]}`
	archonSessionDir := filepath.Join(sessionDir, "archon-audit")
	if err := os.MkdirAll(archonSessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archonSessionDir, "audit-state.json"), []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}

	runner := &AuditAgentRunner{
		cfg:  AuditAgentConfig{SourcePath: sourceDir, SessionDir: sessionDir},
		done: make(chan struct{}),
	}
	close(runner.done) // simulate post-completion

	got := runner.readCurrentState()
	if got == nil {
		t.Fatal("expected state from session-dir fallback, got nil")
	}
	if len(got.Audits) != 1 || got.Audits[0].Status != "complete" {
		t.Fatalf("unexpected state: %+v", got)
	}

	status := runner.Status()
	if status.CompletedPhases != 3 || status.TotalPhases != 3 {
		t.Errorf("expected 3/3 phases, got %d/%d", status.CompletedPhases, status.TotalPhases)
	}
	if status.Status != "complete" {
		t.Errorf("expected status 'complete', got %q", status.Status)
	}
}

// TestImportArchonFindings_StatsWithoutRepo verifies that findings are still
// parsed and counted even when no DB repository is configured, so the CLI
// summary can show what the agent produced.
func TestImportArchonFindings_StatsWithoutRepo(t *testing.T) {
	sessionDir := t.TempDir()
	archonDir := filepath.Join(sessionDir, "archon-audit")
	findingsDir := filepath.Join(archonDir, "findings")
	if err := os.MkdirAll(findingsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Minimal state file so ParseAuditFolder doesn't error.
	stateJSON := `{"audits":[{"audit_id":"t1","mode":"lite","status":"complete","phases":{}}]}`
	if err := os.WriteFile(filepath.Join(archonDir, "audit-state.json"), []byte(stateJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Two promoted findings: one critical, one high.
	writeFinding := func(name, body string) {
		if err := os.WriteFile(filepath.Join(findingsDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFinding("C1.md", "## Q1-001: Hardcoded key\n\n- **Severity**: Critical\n- **File**: app.py\n- **Line**: 10\n- **Verdict**: VALID\n")
	writeFinding("H1.md", "## Q2-001: SQLi\n\n- **Severity**: High\n- **File**: api.py\n- **Line**: 42\n- **Verdict**: VALID\n")

	runner := &AuditAgentRunner{
		cfg:          AuditAgentConfig{SessionDir: sessionDir},
		done:         make(chan struct{}),
		agentRunUUID: "test-run",
	}

	runner.importArchonFindings(context.TODO())

	stats := runner.FindingStats()
	if stats.Parsed != 2 {
		t.Errorf("expected Parsed=2, got %d", stats.Parsed)
	}
	if stats.Saved != 0 {
		t.Errorf("expected Saved=0 (no repo), got %d", stats.Saved)
	}
	if got := stats.BySeverity["critical"]; got != 1 {
		t.Errorf("expected 1 critical, got %d", got)
	}
	if got := stats.BySeverity["high"]; got != 1 {
		t.Errorf("expected 1 high, got %d", got)
	}
}
