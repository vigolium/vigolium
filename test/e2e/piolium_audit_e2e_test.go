//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/piolium/pistream"
)

// TestE2EPioliumAudit_Lite runs `vigolium agent audit --mode lite` against a
// tiny synthetic source tree, end-to-end, through the user's installed Pi
// runtime + piolium extension.
//
// Prerequisites (the test skips when any are missing):
//   - `pi` on $PATH (the @earendil-works/pi-coding-agent npm package)
//   - piolium registered in ~/.pi/agent/settings.json
//   - A working provider — either preconfigured in pi's settings, or
//     overridden via the env vars below.
//
// Provider override (matching the user's two example commands):
//
//	pi --provider google-vertex     --model gemini-3.1-pro    -p "..."
//	pi --provider vertex-anthropic  --model claude-opus-4-6   -p "..."
//
// Env vars consumed by this test:
//   - VIGOLIUM_E2E_PI_PROVIDER  (e.g. "vertex-anthropic", "google-vertex")
//   - VIGOLIUM_E2E_PI_MODEL     (e.g. "claude-opus-4-6", "gemini-3.1-pro")
//   - VIGOLIUM_E2E_PI_TIMEOUT   (Go duration; defaults to 5m)
//   - VIGOLIUM_E2E_PI_KEEP      ("1" to keep the session dir for inspection)
//
// When neither env var is set, the test falls back to whatever
// defaultProvider/defaultModel pi is already configured with — i.e. it
// trusts the user's settings.json.
func TestE2EPioliumAudit_Lite(t *testing.T) {
	skipIfPiUnavailable(t)

	provider := os.Getenv("VIGOLIUM_E2E_PI_PROVIDER")
	model := os.Getenv("VIGOLIUM_E2E_PI_MODEL")
	timeout := parseDurationOrDefault(t, os.Getenv("VIGOLIUM_E2E_PI_TIMEOUT"), 5*time.Minute)
	keepSession := os.Getenv("VIGOLIUM_E2E_PI_KEEP") == "1"

	source := stagePioliumFixture(t)
	sessionDir := stageSessionDir(t, keepSession)

	_, repo := setupTestDB(t)

	streamWriter := &testLogWriter{t: t, prefix: "[pi-stream] "}

	cfg := agent.AuditAgentConfig{
		Harness:      piolium.DefaultHarness(),
		Mode:         "lite",
		Platform:     agent.PlatformPi,
		SourcePath:   source,
		SessionDir:   sessionDir,
		ProjectUUID:  "e2e-pi-project",
		ScanUUID:     "e2e-pi-scan",
		SyncInterval: 5 * time.Second,
		Stream:       true,
		StreamWriter: streamWriter,
		StreamDecoder: func(in io.Reader, render io.Writer, raw io.Writer) error {
			return pistream.Stream(in, render, pistream.Options{RawLog: raw})
		},
		PiProvider: provider,
		PiModel:    model,
	}

	t.Logf("piolium e2e: source=%s sessionDir=%s provider=%q model=%q timeout=%s",
		source, sessionDir, provider, model, timeout)

	runner := agent.NewAuditAgenticScanner(cfg, repo)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	require.NoError(t, runner.Start(ctx), "Start() must succeed when pi+piolium are installed")
	runErr := runner.Wait()
	if runErr != nil {
		t.Logf("audit returned with error (may still be partial-success): %v", runErr)
	}

	// Cancellation due to timeout is the only run-level error we treat as fatal.
	if ctx.Err() != nil {
		t.Fatalf("audit did not finish within %s — increase VIGOLIUM_E2E_PI_TIMEOUT", timeout)
	}

	streamPath := filepath.Join(sessionDir, "audit-stream.jsonl")
	streamInfo, err := os.Stat(streamPath)
	require.NoError(t, err, "audit-stream.jsonl missing — was --mode json correctly invoked?")
	assert.Greater(t, streamInfo.Size(), int64(0), "audit-stream.jsonl is empty")

	// First line proves we actually ran `pi --mode json` and not something else.
	firstLine := readFirstNonEmptyLine(t, streamPath)
	t.Logf("first stream line: %s", truncate(firstLine, 200))
	assert.Contains(t, firstLine, `"type":"session"`,
		"first JSONL line should be Pi's session header")

	// audit-state.json appears once Q0 starts. Tolerate absence — pi may
	// have failed before any phase ran (e.g. provider 401), and the test
	// is still useful for proving the wiring even in that case.
	stateAtSession := filepath.Join(sessionDir, "piolium-audit", "audit-state.json")
	if _, err := os.Stat(stateAtSession); err == nil {
		assertValidState(t, stateAtSession, "lite")
	} else {
		t.Logf("piolium-audit/audit-state.json absent — pi likely failed before Q0; check %s", streamPath)
		dumpAuditStream(t, streamPath, 30)
	}

	gotRun, err := repo.GetAgenticScan(ctx, runner.AgenticScanUUID())
	require.NoError(t, err, "expected the AgenticScan row to exist")
	assert.Equal(t, "piolium", gotRun.Mode, "DB row should be tagged mode=piolium")
	assert.Equal(t, "piolium", gotRun.AgentName)
	assert.Equal(t, "pi-sdk", gotRun.Protocol)
	t.Logf("DB row: status=%s phase=%s phases=%v elapsed=%dms duration=%dms",
		gotRun.Status, gotRun.CurrentPhase, gotRun.PhasesRun, gotRun.DurationMs,
		gotRun.DurationMs)

	// Auth failures and quota exhaustion produce zero-cost transcripts
	// (picost filters them); only assert pricing when cost actually landed.
	if gotRun.EstimatedCostUSD > 0 {
		assert.Greater(t, gotRun.TotalInputTokens, int64(0),
			"non-zero cost should imply non-zero input tokens")
		t.Logf("priced run: $%.4f over %d input + %d output tokens",
			gotRun.EstimatedCostUSD, gotRun.TotalInputTokens, gotRun.TotalOutputTokens)
	} else {
		t.Logf("zero cost recorded — probably an auth/quota failure on the provider side; this is informational only")
	}
}

// --- helpers ---

func skipIfPiUnavailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pi"); err != nil {
		t.Skip("skipping piolium e2e: pi CLI not on $PATH (install: bun install -g @earendil-works/pi-coding-agent)")
	}
	if err := piolium.EnsurePiInstalled(); err != nil {
		t.Skipf("skipping piolium e2e: %v", err)
	}
}

// stagePioliumFixture writes a tiny vulnerable-looking Python file into a
// fresh temp directory and returns its path. Small enough that even a deep
// audit completes quickly, big enough that piolium has something to scan.
func stagePioliumFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"app.py": `# Tiny e2e fixture for vigolium agent audit
import sqlite3
from flask import Flask, request

app = Flask(__name__)
JWT_SECRET = "hardcoded-please-rotate-me"  # Q1 secrets-scan bait

@app.route("/user")
def user():
    name = request.args.get("name")
    cur = sqlite3.connect(":memory:").cursor()
    # Q2 SAST bait: format-string SQL on user input
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchone() or "no user"
`,
		"requirements.txt": "flask==2.0.0\n",
		"README.md":        "# fixture\nA tiny target for vigolium agent audit e2e tests.\n",
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	}
	return dir
}

func stageSessionDir(t *testing.T, keep bool) string {
	t.Helper()
	if !keep {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("", "vigolium-piolium-e2e-")
	require.NoError(t, err)
	t.Logf("VIGOLIUM_E2E_PI_KEEP=1 — preserving session dir: %s", dir)
	return dir
}

func parseDurationOrDefault(t *testing.T, raw string, fallback time.Duration) time.Duration {
	t.Helper()
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		t.Logf("VIGOLIUM_E2E_PI_TIMEOUT %q is not a valid duration; using default %s", raw, fallback)
		return fallback
	}
	return d
}

func readFirstNonEmptyLine(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	// Pi --mode json events can be megabytes (tool results with file contents).
	scanner.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			return scanner.Text()
		}
	}
	return ""
}

func assertValidState(t *testing.T, path, wantMode string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var state struct {
		Audits []struct {
			Mode   string                 `json:"mode"`
			Status string                 `json:"status"`
			Phases map[string]interface{} `json:"phases"`
		} `json:"audits"`
	}
	require.NoError(t, json.Unmarshal(data, &state),
		"audit-state.json must be valid JSON; got: %s", truncate(string(data), 400))
	require.NotEmpty(t, state.Audits, "audit-state.json has no audits[] entry")
	last := state.Audits[len(state.Audits)-1]
	assert.Equal(t, wantMode, last.Mode, "audit-state.json mode mismatch")
	assert.NotEmpty(t, last.Status, "audit-state.json status missing")
	t.Logf("audit-state.json: mode=%s status=%s phases=%d",
		last.Mode, last.Status, len(last.Phases))
}

func dumpAuditStream(t *testing.T, path string, maxLines int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	end := len(lines)
	if end > maxLines {
		end = maxLines
	}
	t.Logf("=== first %d lines of audit-stream.jsonl ===", end)
	for i := 0; i < end; i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		t.Logf("  %s", truncate(lines[i], 240))
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("…(+%d bytes)", len(s)-max)
}

// testLogWriter routes the rendered pi stream into the test log so a `-v`
// run shows the activity feed inline. Color codes survive — most CI
// terminals strip them; locally they make the feed readable.
type testLogWriter struct {
	t      *testing.T
	prefix string
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.t.Log(w.prefix + line)
	}
	return len(p), nil
}
