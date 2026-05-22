package agent

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/audit/stream"
	"github.com/vigolium/vigolium/pkg/database"
)

// newAuditTestRepo builds an in-memory SQLite-backed repository for tests
// that need to exercise CreateAgenticScan / GetAgenticScan. Pattern mirrored
// from pkg/database/record_writer_test.go:newTestDB.
func newAuditTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)
	bunDB := bun.NewDB(sqldb, sqlitedialect.New())
	db := database.NewDBFromBun(bunDB, "sqlite")
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

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

func TestAuditAgentConfig_BalancedMode(t *testing.T) {
	cfg := config.AuditAgentConfig{Mode: "balanced"}
	if got := cfg.EffectiveMode(); got != "balanced" {
		t.Errorf("expected mode 'balanced', got %q", got)
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

func TestState_Parse(t *testing.T) {
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

	// Write state file to simulate audit/ dir in source
	auditDirLocal := filepath.Join(dir, "vigolium-results")
	if err := os.MkdirAll(auditDirLocal, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditDirLocal, "audit-state.json"), []byte(stateJSON), 0644); err != nil {
		t.Fatal(err)
	}

	runner := &AuditAgenticScanner{
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

	// Write state file in source audit/ dir
	auditDirLocal := filepath.Join(sourceDir, "vigolium-results")
	if err := os.MkdirAll(auditDirLocal, 0755); err != nil {
		t.Fatal(err)
	}
	stateContent := `{"audits": [{"status": "in_progress"}]}`
	if err := os.WriteFile(filepath.Join(auditDirLocal, "audit-state.json"), []byte(stateContent), 0644); err != nil {
		t.Fatal(err)
	}

	runner := &AuditAgenticScanner{
		cfg:  AuditAgentConfig{SourcePath: sourceDir, SessionDir: sessionDir},
		done: make(chan struct{}),
	}

	runner.syncStateOnce(context.Background())

	// Verify the state was synced to session dir
	synced, err := os.ReadFile(filepath.Join(sessionDir, "vigolium-results", "audit-state.json"))
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
	runner, err := StartAuditAgent(context.TODO(), cfg, HarnessSpec{}, "/some/source", "/some/session", "proj-1", "scan-1", "", nil, nil)
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
	runner, err := StartAuditAgent(context.TODO(), cfg, HarnessSpec{}, "", "/some/session", "proj-1", "scan-1", "", nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if runner != nil {
		t.Error("expected nil runner when no source path")
	}
}

// auditTestCfg builds an AuditAgentConfig good enough to drive
// buildAuditAgentCommand for the audit platform. SessionDir + ScanUUID
// stay empty because the launcher only reads them in the live runner
// path, not in argv assembly.
func auditTestCfg(mode, sourcePath string, inv AuditDriverInvocation) AuditAgentConfig {
	return AuditAgentConfig{
		Mode:                  mode,
		SourcePath:            sourcePath,
		AuditDriverInvocation: inv,
	}
}

func TestBuildAuditAgentCommand_AuditDriverBin_Headless(t *testing.T) {
	cfg := auditTestCfg("deep", "/tmp/source", AuditDriverInvocation{Agent: AuditDriverAgentClaude})
	binary, args, stdinPrompt, err := buildAuditAgentCommand(PlatformAuditBin, cfg, false)
	if err != nil {
		t.Skipf("vigolium-audit binary not embedded (run `make build-audit`): %v", err)
	}
	if binary == "" {
		t.Error("expected non-empty binary path")
	}
	if stdinPrompt != "" {
		t.Errorf("expected empty stdinPrompt, got %q", stdinPrompt)
	}
	// Headless mode must NOT include --json (so consumers that don't
	// want NDJSON aren't forced into it).
	for _, a := range args {
		if a == "--json" {
			t.Errorf("--json must be omitted in headless mode, got %v", args)
		}
	}
	// Required flags: run subcommand + --target + --mode + --agent.
	wantPairs := map[string]string{
		"--target": "/tmp/source",
		"--mode":   "deep",
		"--agent":  "claude",
	}
	if len(args) == 0 || args[0] != "run" {
		t.Errorf("expected first arg = run, got %v", args)
	}
	for flag, want := range wantPairs {
		if got := flagValue(args, flag); got != want {
			t.Errorf("%s = %q, want %q (args=%v)", flag, got, want, args)
		}
	}
}

func TestBuildAuditAgentCommand_AuditDriverBin_StreamAndAuth(t *testing.T) {
	inv := AuditDriverInvocation{
		Agent: AuditDriverAgentCodex,
		Auth:  AuditDriverAuthFlags{OAuthCredFile: "/secret/codex.json"},
	}
	cfg := auditTestCfg("lite", "/tmp/source", inv)
	_, args, _, err := buildAuditAgentCommand(PlatformAuditBin, cfg, true)
	if err != nil {
		t.Skipf("vigolium-audit binary not embedded: %v", err)
	}
	// --json gates the streaming goroutine — must be present in stream mode.
	foundJSON := false
	for _, a := range args {
		if a == "--json" {
			foundJSON = true
		}
	}
	if !foundJSON {
		t.Errorf("--json should be appended in stream mode, got %v", args)
	}
	if got := flagValue(args, "--agent"); got != "codex" {
		t.Errorf("--agent = %q, want codex", got)
	}
	if got := flagValue(args, "--oauth-cred-file"); got != "/secret/codex.json" {
		t.Errorf("--oauth-cred-file = %q, want /secret/codex.json", got)
	}
}

func TestBuildAuditAgentCommand_Pi(t *testing.T) {
	cfg := AuditAgentConfig{Mode: "lite", SourcePath: "/tmp/source"}
	binary, args, _, err := buildAuditAgentCommand(PlatformPi, cfg, true)
	if err != nil {
		t.Skipf("pi not in PATH: %v", err)
	}
	if binary == "" {
		t.Error("expected non-empty pi binary")
	}
	want := []string{"--mode", "json", "-p", "/piolium-lite"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("pi args = %v, want %v", args, want)
	}
}

func TestBuildAuditAgentCommand_Pi_PrependsProviderAndModel(t *testing.T) {
	cfg := AuditAgentConfig{
		Mode:           "balanced",
		SourcePath:     "/tmp/source",
		PiProvider:     "vertex-anthropic",
		PiModel:        "claude-opus-4-6",
		AdditionalArgs: []string{"--plm-scan-limit", "100"},
	}
	_, args, _, err := buildAuditAgentCommand(PlatformPi, cfg, true)
	if err != nil {
		t.Skipf("pi not in PATH: %v", err)
	}
	want := []string{
		"--provider", "vertex-anthropic",
		"--model", "claude-opus-4-6",
		"--mode", "json",
		"-p", "/piolium-balanced",
		"--plm-scan-limit", "100",
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("pi args = %v, want %v", args, want)
	}
}

// When the caller supplies a session dir, pi must receive
// --session-dir <session>/pi-session so its transcripts/state are
// per-scan and co-located with audit-stream.jsonl. The flag is
// inserted between piPreArgs (provider/model) and the --mode/--p
// pair so pi parses it as its own knob, not as a /piolium-* arg.
func TestBuildAuditAgentCommand_Pi_SessionDir(t *testing.T) {
	cfg := AuditAgentConfig{Mode: "lite", SourcePath: "/tmp/source", SessionDir: "/tmp/sess"}
	_, args, _, err := buildAuditAgentCommand(PlatformPi, cfg, true)
	if err != nil {
		t.Skipf("pi not in PATH: %v", err)
	}
	want := []string{"--session-dir", "/tmp/sess/pi-session", "--mode", "json", "-p", "/piolium-lite"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("pi args = %v, want %v", args, want)
	}
}

func TestBuildAuditAgentCommand_Pi_SessionDir_OmittedWhenEmpty(t *testing.T) {
	cfg := AuditAgentConfig{Mode: "lite", SourcePath: "/tmp/source"}
	_, args, _, err := buildAuditAgentCommand(PlatformPi, cfg, true)
	if err != nil {
		t.Skipf("pi not in PATH: %v", err)
	}
	for _, a := range args {
		if a == "--session-dir" {
			t.Errorf("expected no --session-dir when sessionDir is empty, got args=%v", args)
		}
	}
}

// flagValue returns the value following flag in argv, or "" when flag is absent.
func flagValue(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

func TestPiPreArgs_OmitsEmpty(t *testing.T) {
	if got := piPreArgs(AuditAgentConfig{}); len(got) != 0 {
		t.Errorf("empty config should yield empty piPreArgs, got %v", got)
	}
	if got := piPreArgs(AuditAgentConfig{PiProvider: "google-vertex"}); !reflect.DeepEqual(got, []string{"--provider", "google-vertex"}) {
		t.Errorf("provider-only got %v", got)
	}
	if got := piPreArgs(AuditAgentConfig{PiModel: "gemini-3.1-pro"}); !reflect.DeepEqual(got, []string{"--model", "gemini-3.1-pro"}) {
		t.Errorf("model-only got %v", got)
	}
}

// TestPiPreArgs_DocumentedExamples freezes the argv shape for the two
// provider/model combinations called out in docs/agentic-scan/piolium-audit.md
// — equivalent to `pi --provider <p> --model <m> -p ...`. Catches regressions
// in flag plumbing without needing pi or network access.
func TestPiPreArgs_DocumentedExamples(t *testing.T) {
	cases := []struct {
		provider, model string
		want            []string
	}{
		{"google-vertex", "gemini-3.1-pro", []string{"--provider", "google-vertex", "--model", "gemini-3.1-pro"}},
		{"vertex-anthropic", "claude-opus-4-6", []string{"--provider", "vertex-anthropic", "--model", "claude-opus-4-6"}},
	}
	for _, c := range cases {
		got := piPreArgs(AuditAgentConfig{PiProvider: c.provider, PiModel: c.model})
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("provider=%s model=%s: got %v, want %v", c.provider, c.model, got, c.want)
		}
	}
}

// TestReadCurrentState_SessionDirFallback verifies that Status() can recover
// the audit state after monitor() has removed SourcePath/audit/ — the CLI
// summary is the primary consumer and runs after cleanup.
func TestReadCurrentState_SessionDirFallback(t *testing.T) {
	sourceDir := t.TempDir()
	sessionDir := t.TempDir()

	// Only write the state file into the session dir, not the source dir.
	state := `{"audits":[{"audit_id":"t1","status":"complete","phases":{"Q0":{"status":"complete"},"Q1":{"status":"complete"},"Q2":{"status":"complete"}}}]}`
	auditSessionDir := filepath.Join(sessionDir, "vigolium-results")
	if err := os.MkdirAll(auditSessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditSessionDir, "audit-state.json"), []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}

	runner := &AuditAgenticScanner{
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

// TestImportFindings_StatsWithoutRepo verifies that findings are still
// parsed and counted even when no DB repository is configured, so the CLI
// summary can show what the agent produced.
func TestImportFindings_StatsWithoutRepo(t *testing.T) {
	sessionDir := t.TempDir()
	auditDirLocal := filepath.Join(sessionDir, "vigolium-results")
	findingsDir := filepath.Join(auditDirLocal, "findings")
	if err := os.MkdirAll(findingsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Minimal state file so ParseFolder doesn't error.
	stateJSON := `{"audits":[{"audit_id":"t1","mode":"lite","status":"complete","phases":{}}]}`
	if err := os.WriteFile(filepath.Join(auditDirLocal, "audit-state.json"), []byte(stateJSON), 0o644); err != nil {
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

	runner := &AuditAgenticScanner{
		cfg:             AuditAgentConfig{SessionDir: sessionDir},
		done:            make(chan struct{}),
		agenticScanUUID: "test-run",
	}

	runner.importFindings(context.TODO())

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

// TestImportFindings_AuditStreamFallback verifies that when on-disk parsing
// yields no findings but the audit binary's NDJSON `result` event reported
// some, the runner surfaces those counts via FindingStats.Reported /
// ReportedBySeverity so the CLI summary mirrors the streamer's [result] line.
// Severity keys from the stream (TitleCase) are normalized to lowercase.
func TestImportFindings_AuditStreamFallback(t *testing.T) {
	sessionDir := t.TempDir()
	auditDirLocal := filepath.Join(sessionDir, "vigolium-results")
	if err := os.MkdirAll(auditDirLocal, 0o755); err != nil {
		t.Fatal(err)
	}
	// Minimal state file so ParseFolder doesn't error; no findings/ dir.
	stateJSON := `{"audits":[{"audit_id":"t1","mode":"lite","status":"complete","phases":{}}]}`
	if err := os.WriteFile(filepath.Join(auditDirLocal, "audit-state.json"), []byte(stateJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	runner := &AuditAgenticScanner{
		cfg:             AuditAgentConfig{SessionDir: sessionDir},
		done:            make(chan struct{}),
		agenticScanUUID: "test-run",
		auditResult: stream.Result{
			Status: "complete",
			Findings: stream.Findings{
				Total: 13,
				BySeverity: map[string]int{
					"High":   6,
					"Medium": 5,
					"Low":    2,
				},
			},
		},
	}

	runner.importFindings(context.TODO())

	stats := runner.FindingStats()
	if stats.Parsed != 0 {
		t.Errorf("expected Parsed=0 (no findings on disk), got %d", stats.Parsed)
	}
	if stats.Reported != 13 {
		t.Errorf("expected Reported=13 from audit stream, got %d", stats.Reported)
	}
	if got := stats.ReportedBySeverity["high"]; got != 6 {
		t.Errorf("expected 6 high (lowercased), got %d", got)
	}
	if got := stats.ReportedBySeverity["medium"]; got != 5 {
		t.Errorf("expected 5 medium (lowercased), got %d", got)
	}
	if got := stats.ReportedBySeverity["low"]; got != 2 {
		t.Errorf("expected 2 low (lowercased), got %d", got)
	}
	// Breakdown string falls back to ReportedBySeverity when Parsed == 0.
	if got := stats.SeverityBreakdownString(); got == "" {
		t.Errorf("expected non-empty breakdown from reported severities")
	}
}

// --- Regression: audit session UUID must be resolvable to runtime.log ---
//
// Background: a previous bug had NewAuditAgenticScanner call uuid.New()
// independently of the caller's chosen session directory, so the standalone
// audit AgenticScan row's UUID and ~/.vigolium/agent-sessions/<dir> name
// diverged. `vigolium log ls` then listed a UUID whose session directory
// didn't exist and `vigolium log <uuid>` errored.
//
// The fix is nuanced: standalone audit MUST unify UUID with the session dir
// name, but nested audit (spawned by autopilot/swarm) MUST NOT — otherwise
// the child row collides with the parent's UUID (both share one SessionDir).
// The ParentAgenticScanUUID field is the signal.
//
// The four tests below lock in the invariants that prevent regression:
//   1. Standalone (SessionDir set, ParentAgenticScanUUID empty): UUID == filepath.Base(SessionDir).
//   2. Nested (SessionDir set, ParentAgenticScanUUID set): UUID is a fresh random UUID,
//      never equal to filepath.Base(SessionDir), so the parent/child rows don't collide.
//   3. No SessionDir: UUID is still a valid random UUID.
//   4. createAgenticScan persists SessionDir on the row so resolveLogSource's
//      DB-backed fallback can find runtime.log for the nested-child case.

func TestNewAuditAgenticScanner_StandaloneUUIDMatchesSessionDir(t *testing.T) {
	knownUUID := "445734a3-5a33-4bb9-b581-b837b5aede8a"
	sessionDir := filepath.Join(t.TempDir(), knownUUID)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	scanner := NewAuditAgenticScanner(AuditAgentConfig{SessionDir: sessionDir}, nil)

	if got := scanner.agenticScanUUID; got != knownUUID {
		t.Errorf("standalone agenticScanUUID = %q, want %q (filepath.Base of SessionDir) — "+
			"standalone audit's DB row UUID must match the on-disk dir name or "+
			"`vigolium log <uuid>` breaks",
			got, knownUUID)
	}
}

func TestNewAuditAgenticScanner_NestedDoesNotCollideWithParent(t *testing.T) {
	// Simulate the autopilot/swarm case: the parent owns sessionDir and a row
	// whose UUID equals filepath.Base(sessionDir). Audit is spawned as a
	// child with the SAME SessionDir (shared for artifacts) and must get its
	// own UUID so CreateAgenticScan doesn't collide on primary key.
	parentUUID := "445734a3-5a33-4bb9-b581-b837b5aede8a"
	sessionDir := filepath.Join(t.TempDir(), parentUUID)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	scanner := NewAuditAgenticScanner(AuditAgentConfig{
		SessionDir:            sessionDir,
		ParentAgenticScanUUID: parentUUID,
	}, nil)

	if scanner.agenticScanUUID == parentUUID {
		t.Errorf("nested audit's UUID == parent UUID (%q) — createAgenticScan would "+
			"collide with the parent's row on primary key",
			parentUUID)
	}
	if scanner.agenticScanUUID == filepath.Base(sessionDir) {
		t.Errorf("nested audit's UUID = %q matches filepath.Base(SessionDir) — "+
			"it must differ so the child row is distinct from the parent",
			scanner.agenticScanUUID)
	}
	if _, err := uuid.Parse(scanner.agenticScanUUID); err != nil {
		t.Errorf("nested agenticScanUUID = %q is not a valid UUID: %v", scanner.agenticScanUUID, err)
	}
}

func TestNewAuditAgenticScanner_NoSessionDirGeneratesUUID(t *testing.T) {
	scanner := NewAuditAgenticScanner(AuditAgentConfig{}, nil)

	if scanner.agenticScanUUID == "" {
		t.Fatal("agenticScanUUID was empty — expected a generated UUID")
	}
	if _, err := uuid.Parse(scanner.agenticScanUUID); err != nil {
		t.Errorf("agenticScanUUID = %q is not a valid UUID: %v", scanner.agenticScanUUID, err)
	}
}

func TestCreateAgenticScan_PersistsSessionDirStandalone(t *testing.T) {
	repo := newAuditTestRepo(t)
	ctx := context.Background()

	sessionUUID := uuid.New().String()
	sessionDir := filepath.Join(t.TempDir(), sessionUUID)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	scanner := NewAuditAgenticScanner(AuditAgentConfig{
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
		SourcePath:  "/tmp/source",
	}, repo)

	scanner.createAgenticScan(ctx)

	row, err := repo.GetAgenticScan(ctx, sessionUUID)
	if err != nil {
		t.Fatalf("GetAgenticScan(%q): %v — standalone row UUID must match session dir name", sessionUUID, err)
	}
	if row.UUID != sessionUUID {
		t.Errorf("row.UUID = %q, want %q", row.UUID, sessionUUID)
	}
	if row.SessionDir != sessionDir {
		t.Errorf("row.SessionDir = %q, want %q — resolveLogSource's DB fallback relies on this", row.SessionDir, sessionDir)
	}
}

func TestCreateAgenticScan_PersistsSessionDirNested(t *testing.T) {
	// The nested case: parent owns a row at filepath.Base(sessionDir). Child
	// audit must create a DISTINCT row that still carries SessionDir so
	// `vigolium log <child-uuid>` can resolve runtime.log via the DB fallback
	// (the child UUID won't match any on-disk directory).
	repo := newAuditTestRepo(t)
	ctx := context.Background()

	parentUUID := uuid.New().String()
	sessionDir := filepath.Join(t.TempDir(), parentUUID)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Pre-create parent row to assert no collision when child inserts.
	parentRow := &database.AgenticScan{
		UUID:        parentUUID,
		ProjectUUID: database.DefaultProjectUUID,
		Mode:        "autopilot",
		Status:      "running",
		SessionDir:  sessionDir,
	}
	if err := repo.CreateAgenticScan(ctx, parentRow); err != nil {
		t.Fatalf("pre-create parent: %v", err)
	}

	scanner := NewAuditAgenticScanner(AuditAgentConfig{
		SessionDir:            sessionDir,
		ParentAgenticScanUUID: parentUUID,
		ProjectUUID:           database.DefaultProjectUUID,
		SourcePath:            "/tmp/source",
	}, repo)

	scanner.createAgenticScan(ctx)

	// Child must be retrievable by its own (fresh) UUID.
	childRow, err := repo.GetAgenticScan(ctx, scanner.agenticScanUUID)
	if err != nil {
		t.Fatalf("GetAgenticScan(child=%q): %v — nested audit row must exist with fresh UUID", scanner.agenticScanUUID, err)
	}
	if childRow.UUID == parentUUID {
		t.Error("child UUID equals parent UUID — createAgenticScan should have used a fresh UUID to avoid collision")
	}
	if childRow.SessionDir != sessionDir {
		t.Errorf("child row SessionDir = %q, want %q — required for resolveLogSource's DB fallback", childRow.SessionDir, sessionDir)
	}
	if childRow.ParentAgenticScanUUID != parentUUID {
		t.Errorf("child row ParentAgenticScanUUID = %q, want %q", childRow.ParentAgenticScanUUID, parentUUID)
	}
}

func TestIsSharedAuditMode(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"lite", true},
		{"balanced", true},
		{"scan", true},
		{"deep", true},
		{"revisit", true},
		{"confirm", true},
		{"merge", true},

		{"longshot", false}, // piolium-only
		{"smoke", false},    // piolium-only
		{"mock", false},     // audit-only
		{"diff", false},     // not in shared set
		{"status", false},   // not in shared set
		{"", false},
		{"random", false},
	}
	for _, tc := range cases {
		if got := IsSharedAuditMode(tc.mode); got != tc.want {
			t.Errorf("IsSharedAuditMode(%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}
