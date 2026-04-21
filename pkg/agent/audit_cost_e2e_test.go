//go:build e2e

// End-to-end coverage for the archon cost-tracking pipeline. Each test
// wires a realistic backend-specific transcript fixture through the
// real code path (claudecost/codexcost parse → scanCostFrom* adapter →
// applyScanCost) and asserts the resulting database.AgenticScan row.
//
// Run with: go test -tags=e2e ./pkg/agent/...
package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/archon/claudecost"
	"github.com/vigolium/vigolium/pkg/archon/codexcost"
	"github.com/vigolium/vigolium/pkg/database"
)

// setupTestDB mirrors the helper in test/e2e/ — in-memory SQLite with schema.
func setupTestDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        ":memory:",
			BusyTimeout: 5000,
			JournalMode: "MEMORY",
			Synchronous: "OFF",
			CacheSize:   10000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { _ = db.Close() })
	return db, database.NewRepository(db)
}

// writeMainStreamFixture drops a realistic Claude audit-stream.jsonl that
// covers the shapes the parser actually sees: init, assistant messages
// with cumulative usage per message.id, and a final result event with
// total_cost_usd.
func writeMainStreamFixture(t *testing.T, path string) {
	t.Helper()
	// Cumulative-per-message-id: the later line for msg_A must replace
	// the earlier one; msg_B adds on top. Final sums:
	//   input=53, output=1650, cache_read=3_518_062, cache_create_1h=156_217
	lines := []string{
		`{"type":"system","subtype":"init","session_id":"sess-main-1","cwd":"/Users/test/repo","model":"claude-opus-4-7[1m]"}`,
		`{"type":"assistant","message":{"id":"msg_A","model":"claude-opus-4-7[1m]","usage":{"input_tokens":50,"output_tokens":600,"cache_read_input_tokens":2000000,"cache_creation_input_tokens":100000,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":100000}}}}`,
		`{"type":"assistant","message":{"id":"msg_A","model":"claude-opus-4-7[1m]","usage":{"input_tokens":50,"output_tokens":1500,"cache_read_input_tokens":3500000,"cache_creation_input_tokens":150000,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":150000}}}}`,
		`{"type":"assistant","message":{"id":"msg_B","model":"claude-opus-4-7[1m]","usage":{"input_tokens":3,"output_tokens":150,"cache_read_input_tokens":18062,"cache_creation_input_tokens":6217,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":6217}}}}`,
		`{"type":"result","subtype":"success","duration_ms":27000,"num_turns":4,"total_cost_usd":8.42,"result":"done"}`,
	}
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
}

// writeSubagentFixture drops one async-agent transcript. The first line
// carries the `agentId` field — this is what distinguishes real subagent
// outputs from the bash-background task files that share the directory.
func writeSubagentFixture(t *testing.T, dir, agentID string, inputTokens, outputTokens, cacheRead int64) {
	t.Helper()
	path := filepath.Join(dir, agentID+".output")
	lines := []string{
		fmt.Sprintf(`{"agentId":"%s","type":"user","message":{}}`, agentID),
		fmt.Sprintf(`{"type":"system","subtype":"init","session_id":"sub-%s","cwd":"/Users/test/repo","model":"claude-sonnet-4-6"}`, agentID),
		fmt.Sprintf(`{"type":"assistant","message":{"id":"msg_S","model":"claude-sonnet-4-6","usage":{"input_tokens":%d,"output_tokens":%d,"cache_read_input_tokens":%d}}}`,
			inputTokens, outputTokens, cacheRead),
	}
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
}

// writeBashBackgroundOutput drops a file that lives in the same tasks
// directory as subagent outputs but has no agentId — FindSubagentFiles
// must skip it.
func writeBashBackgroundOutput(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "bn42nz1aj.output")
	require.NoError(t, os.WriteFile(path, []byte("running semgrep...\ndone\n"), 0o644))
}

// TestE2E_ClaudeCostFullPipeline exercises the whole cost chain for a
// Claude archon run: fixture file → claudecost.BuildSummaryWithTasksDir
// → scanCostFromClaude → applyScanCost → DB row readback.
func TestE2E_ClaudeCostFullPipeline(t *testing.T) {
	_, repo := setupTestDB(t)

	sessionDir := t.TempDir()
	tasksDir := t.TempDir()

	writeMainStreamFixture(t, filepath.Join(sessionDir, "audit-stream.jsonl"))
	// Three subagents of varying sizes + one non-subagent bash output to
	// confirm filtering works.
	writeSubagentFixture(t, tasksDir, "a111111111111", 500, 10_000, 900_000)
	writeSubagentFixture(t, tasksDir, "a222222222222", 600, 8_000, 700_000)
	writeSubagentFixture(t, tasksDir, "a333333333333", 700, 6_000, 500_000)
	writeBashBackgroundOutput(t, tasksDir)

	// Parse.
	s, err := claudecost.BuildSummaryWithTasksDir(
		filepath.Join(sessionDir, "audit-stream.jsonl"),
		tasksDir,
	)
	require.NoError(t, err)

	// Assertions on the parsed Summary.
	assert.Equal(t, "claude-opus-4-7[1m]", s.Model)
	assert.Equal(t, "sess-main-1", s.SessionID)
	assert.Equal(t, 8.42, s.MainCostReported, "result.total_cost_usd must be captured")
	assert.Len(t, s.Subagents, 3, "bash-background output should be filtered out")
	// Main deduped usage: msg_A final (50, 1500, 3_500_000, 150_000) + msg_B (3, 150, 18_062, 6_217)
	assert.Equal(t, int64(53), s.Main.InputTokens)
	assert.Equal(t, int64(1650), s.Main.OutputTokens)
	assert.Equal(t, int64(3_518_062), s.Main.CacheReadTokens)
	assert.Equal(t, int64(156_217), s.Main.CacheCreateTokens)

	// Main cost preference: reported wins over local estimate.
	// TotalCostUSD = reported main + priced subagents.
	assert.Greater(t, s.TotalCostUSD, s.MainCostReported)

	// Adapt to ScanCost.
	cost := scanCostFromClaude(s)
	assert.Equal(t, "claude", cost.Backend)
	assert.Equal(t, "claude-opus-4-7[1m]", cost.Model)
	// DB totals should include subagent tokens.
	assert.Equal(t, int64(53+500+600+700), cost.InputTokens)
	assert.Equal(t, int64(1650+10_000+8_000+6_000), cost.OutputTokens)
	assert.Contains(t, cost.Note, "3 subagents")
	assert.Contains(t, cost.Note, "$8.42", "Note must cite the reported main cost")
	assert.NotNil(t, cost.Blob, "Blob must be populated for JSONB persistence")

	// Persist to DB.
	ctx := context.Background()
	run := &database.AgenticScan{
		UUID:        "test-run-claude",
		ProjectUUID: database.DefaultProjectUUID,
		Mode:        "archon",
		AgentName:   "archon-audit",
		Protocol:    "sdk",
		Status:      "running",
		StartedAt:   time.Now().Add(-1 * time.Minute),
	}
	require.NoError(t, repo.CreateAgenticScan(ctx, run))
	applyScanCost(run, cost)
	require.NoError(t, repo.UpdateAgenticScan(ctx, run))

	// Read back and verify persisted columns.
	got, err := repo.GetAgenticScan(ctx, "test-run-claude")
	require.NoError(t, err)
	assert.Equal(t, "claude-opus-4-7[1m]", got.Model)
	assert.Equal(t, cost.InputTokens, got.TotalInputTokens)
	assert.Equal(t, cost.OutputTokens, got.TotalOutputTokens)
	assert.InDelta(t, cost.CostUSD, got.EstimatedCostUSD, 0.001)
	assert.NotNil(t, got.TokenUsage, "TokenUsage JSONB must be persisted")
	// The JSONB round-trip must carry the subagent breakdown.
	assert.Contains(t, got.TokenUsage, "subagents")
}

// TestE2E_ClaudeCostNoSubagents verifies the main-only path end-to-end.
func TestE2E_ClaudeCostNoSubagents(t *testing.T) {
	_, repo := setupTestDB(t)

	sessionDir := t.TempDir()
	writeMainStreamFixture(t, filepath.Join(sessionDir, "audit-stream.jsonl"))

	// Pass a fresh empty tasksDir — FindSubagentFiles must handle the
	// "no subagent outputs" case cleanly.
	s, err := claudecost.BuildSummaryWithTasksDir(
		filepath.Join(sessionDir, "audit-stream.jsonl"),
		t.TempDir(),
	)
	require.NoError(t, err)
	assert.Empty(t, s.Subagents)

	cost := scanCostFromClaude(s)
	assert.Contains(t, cost.Note, "main only")
	assert.Equal(t, 8.42, cost.CostUSD, "main-only cost should be the reported total")

	ctx := context.Background()
	run := &database.AgenticScan{
		UUID:        "test-run-claude-main",
		ProjectUUID: database.DefaultProjectUUID,
		Mode:        "archon",
		AgentName:   "archon-audit",
		Status:      "running",
		StartedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateAgenticScan(ctx, run))
	applyScanCost(run, cost)
	require.NoError(t, repo.UpdateAgenticScan(ctx, run))

	got, err := repo.GetAgenticScan(ctx, "test-run-claude-main")
	require.NoError(t, err)
	assert.Equal(t, int64(53), got.TotalInputTokens)
	assert.InDelta(t, 8.42, got.EstimatedCostUSD, 0.001)
}

// writeCodexRollout drops a realistic Codex session rollout under the
// given codexHome date directory.
func writeCodexRollout(t *testing.T, codexHome string, startedAt time.Time, cwd, model, sessionID string, usage codexcost.Usage) string {
	t.Helper()
	dayDir := filepath.Join(codexHome, "sessions",
		fmt.Sprintf("%04d", startedAt.Year()),
		fmt.Sprintf("%02d", int(startedAt.Month())),
		fmt.Sprintf("%02d", startedAt.Day()),
	)
	require.NoError(t, os.MkdirAll(dayDir, 0o755))
	path := filepath.Join(dayDir, "rollout-"+sessionID+".jsonl")
	ts := startedAt.UTC().Format("2006-01-02T15:04:05.000Z")
	lines := []string{
		fmt.Sprintf(`{"type":"session_meta","payload":{"id":"%s","cwd":"%s","timestamp":"%s"}}`, sessionID, cwd, ts),
		fmt.Sprintf(`{"type":"turn_context","payload":{"model":"%s"}}`, model),
		// Intermediate partial — must be ignored in favor of the last.
		`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1000,"cached_input_tokens":500,"output_tokens":50,"reasoning_output_tokens":20,"total_tokens":1050}}}}`,
		fmt.Sprintf(
			`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":%d,"cached_input_tokens":%d,"output_tokens":%d,"reasoning_output_tokens":%d,"total_tokens":%d}}}}`,
			usage.InputTokens, usage.CachedInputTokens, usage.OutputTokens, usage.ReasoningOutputTokens, usage.TotalTokens,
		),
	}
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	return path
}

// TestE2E_CodexCostFullPipeline exercises the Codex chain: rollout file
// located via CODEX_HOME override → codexcost.BuildSummary →
// scanCostFromCodex → applyScanCost → DB row readback.
func TestE2E_CodexCostFullPipeline(t *testing.T) {
	_, repo := setupTestDB(t)

	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)

	startedAt := time.Now().Add(-30 * time.Second)
	cwd := "/Users/test/codex-repo"
	usage := codexcost.Usage{
		InputTokens:           169_325,
		CachedInputTokens:     118_272,
		OutputTokens:          1_818,
		ReasoningOutputTokens: 1_080,
		TotalTokens:           171_143,
	}
	writeCodexRollout(t, codexHome, startedAt, cwd, "gpt-5.4", "sess-codex-e2e", usage)

	s, err := codexcost.BuildSummary(cwd, startedAt)
	require.NoError(t, err)
	assert.Equal(t, "sess-codex-e2e", s.SessionID)
	assert.Equal(t, "gpt-5.4", s.Model)
	assert.Equal(t, cwd, s.CWD)
	assert.Equal(t, usage, s.Usage, "final token_count must override earlier partials")
	assert.InDelta(t, 0.1076, s.TotalCostUSD, 0.005)

	cost := scanCostFromCodex(s)
	assert.Equal(t, "codex", cost.Backend)
	// Codex records input_tokens including cached; we persist that so
	// downstream tooling can split by consulting the JSONB blob.
	assert.Equal(t, int64(169_325), cost.InputTokens)
	// Reasoning tokens are rolled into OutputTokens for DB accounting.
	assert.Equal(t, int64(1_818+1_080), cost.OutputTokens)

	ctx := context.Background()
	run := &database.AgenticScan{
		UUID:        "test-run-codex",
		ProjectUUID: database.DefaultProjectUUID,
		Mode:        "archon",
		AgentName:   "archon-audit",
		Protocol:    "codex-sdk",
		Status:      "running",
		StartedAt:   startedAt,
	}
	require.NoError(t, repo.CreateAgenticScan(ctx, run))
	applyScanCost(run, cost)
	require.NoError(t, repo.UpdateAgenticScan(ctx, run))

	got, err := repo.GetAgenticScan(ctx, "test-run-codex")
	require.NoError(t, err)
	assert.Equal(t, "gpt-5.4", got.Model)
	assert.Equal(t, int64(169_325), got.TotalInputTokens)
	assert.Equal(t, int64(1_818+1_080), got.TotalOutputTokens)
	assert.InDelta(t, 0.1076, got.EstimatedCostUSD, 0.005)
	// Blob should expose the raw codex fields.
	require.NotNil(t, got.TokenUsage)
	usageBlob, ok := got.TokenUsage["usage"].(map[string]interface{})
	require.True(t, ok, "token_usage blob must contain nested usage object")
	assert.EqualValues(t, 118_272, usageBlob["cached_input_tokens"])
}

// TestE2E_ComputeCostSummary_ClaudeBackend wires up an AuditAgenticScanner
// with a real session dir fixture and triggers the private computeCostSummary
// path the same way finalizeAgenticScan does. This is the highest-fidelity
// coverage without spawning a real Claude subprocess.
func TestE2E_ComputeCostSummary_ClaudeBackend(t *testing.T) {
	sessionDir := t.TempDir()
	writeMainStreamFixture(t, filepath.Join(sessionDir, "audit-stream.jsonl"))

	runner := &AuditAgenticScanner{
		cfg: AuditAgentConfig{
			Platform:   archon.PlatformClaude,
			SessionDir: sessionDir,
			SourcePath: "/Users/test/repo",
		},
		done: make(chan struct{}),
	}
	runner.computeCostSummary()

	got := runner.CostSummary()
	require.False(t, got.IsZero(), "computeCostSummary should produce a non-zero ScanCost for a valid fixture")
	assert.Equal(t, "claude", got.Backend)
	assert.Equal(t, "claude-opus-4-7[1m]", got.Model)
	assert.Contains(t, got.Note, "main only")
	assert.InDelta(t, 8.42, got.CostUSD, 0.001)
}

// TestE2E_ComputeCostSummary_CodexBackend exercises the Codex branch of
// computeCostSummary via a CODEX_HOME override.
func TestE2E_ComputeCostSummary_CodexBackend(t *testing.T) {
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)

	cwd := "/Users/test/codex-repo"
	startedAt := time.Now().Add(-10 * time.Second)
	writeCodexRollout(t, codexHome, startedAt, cwd, "gpt-5.4", "sess-compute", codexcost.Usage{
		InputTokens:           10_000,
		CachedInputTokens:     5_000,
		OutputTokens:          200,
		ReasoningOutputTokens: 100,
		TotalTokens:           10_200,
	})

	runner := &AuditAgenticScanner{
		cfg: AuditAgentConfig{
			Platform:   archon.PlatformCodex,
			SourcePath: cwd,
		},
		done:      make(chan struct{}),
		startedAt: startedAt,
	}
	runner.computeCostSummary()

	got := runner.CostSummary()
	require.False(t, got.IsZero())
	assert.Equal(t, "codex", got.Backend)
	assert.Equal(t, "gpt-5.4", got.Model)
	assert.Equal(t, int64(300), got.OutputTokens, "output+reasoning rolled up")
}

// TestE2E_ComputeCostSummary_UnsupportedBackend confirms that
// unsupported backends (opencode, empty) leave costSummary zero.
func TestE2E_ComputeCostSummary_UnsupportedBackend(t *testing.T) {
	runner := &AuditAgenticScanner{
		cfg: AuditAgentConfig{
			Platform:   archon.PlatformOpenCode,
			SessionDir: t.TempDir(),
			SourcePath: "/tmp",
		},
		done: make(chan struct{}),
	}
	runner.computeCostSummary()
	assert.True(t, runner.CostSummary().IsZero(), "OpenCode backend should yield no cost")
}
