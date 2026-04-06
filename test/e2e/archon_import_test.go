//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/database"
)

func archonTestdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata", "archon-audit-data")
}

func exportDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata", "vigolium-export")
}

func TestArchonImport_HarborFullPipeline(t *testing.T) {
	harborDir := filepath.Join(archonTestdataDir(), "archon-output-harbor")

	// Parse the archon output folder
	result, err := archon.ParseAuditFolder(harborDir)
	require.NoError(t, err)
	require.NotNil(t, result.State)
	require.NotEmpty(t, result.RawFindings)

	// Set up in-memory DB
	db, repo := setupTestDB(t)
	ctx := context.Background()

	// Build and create AgentRun
	agentRun := archon.BuildAgentRun(result.State, harborDir, database.DefaultProjectUUID)
	require.NotEmpty(t, agentRun.UUID)
	err = repo.CreateAgentRun(ctx, agentRun)
	require.NoError(t, err)

	// Verify AgentRun was stored
	storedRun, err := repo.GetAgentRun(ctx, agentRun.UUID)
	require.NoError(t, err)
	assert.Equal(t, "archon", storedRun.Mode)
	assert.Equal(t, "archon-audit", storedRun.AgentName)
	assert.Equal(t, "completed", storedRun.Status)
	assert.Equal(t, "archon", storedRun.InputType)
	assert.Contains(t, storedRun.InputRaw, "commit:")
	assert.Contains(t, storedRun.InputRaw, "branch:audit")
	assert.Len(t, storedRun.PhasesRun, 11)
	assert.Equal(t, 47, storedRun.FindingCount)
	assert.NotEmpty(t, storedRun.ResultJSON)
	assert.True(t, storedRun.DurationMs > 0)

	// Build and save findings
	auditID := result.State.Audits[0].AuditID
	findings := archon.BuildFindings(result.RawFindings, auditID, agentRun.UUID, database.DefaultProjectUUID, result.RepoName)
	require.NotEmpty(t, findings)

	saved, skipped := 0, 0
	for _, f := range findings {
		err := repo.SaveFindingDirect(ctx, f)
		require.NoError(t, err)
		if f.ID == 0 {
			skipped++
		} else {
			saved++
		}
	}

	assert.True(t, saved > 30, "expected > 30 saved findings, got %d", saved)
	assert.Equal(t, 0, skipped, "no duplicates expected on first import")

	// Verify findings in DB
	var dbFindings []*database.Finding
	err = db.NewSelect().Model(&dbFindings).
		Where("project_uuid = ?", database.DefaultProjectUUID).
		OrderExpr("module_id ASC").
		Scan(ctx)
	require.NoError(t, err)
	assert.Equal(t, saved, len(dbFindings))

	// Verify field mappings on a known finding
	var p7001 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleID == "archon:p7-001" {
			p7001 = f
			break
		}
	}
	require.NotNil(t, p7001, "should find archon:p7-001 in DB")
	assert.Equal(t, "Open Redirect via Unvalidated postURI in Auth-Proxy Controller", p7001.ModuleName)
	assert.Equal(t, "high", p7001.Severity)
	assert.Equal(t, "firm", p7001.Confidence)
	assert.Equal(t, database.ModuleTypeWhitebox, p7001.ModuleType)
	assert.Equal(t, database.FindingSourceArchon, p7001.FindingSource)
	assert.Equal(t, "open-redirect-authproxy", p7001.ModuleShort)
	assert.Equal(t, "CWE-601", p7001.CWEID)
	assert.Equal(t, agentRun.UUID, p7001.AgentRunUUID)
	assert.Contains(t, p7001.Tags, "archon")
	assert.Contains(t, p7001.Tags, "phase-7")
	assert.NotEmpty(t, p7001.Description)
	assert.NotEmpty(t, p7001.MatchedAt)
	assert.Equal(t, "https://github.com/goharbor/harbor", p7001.RepoName, "repo name should be persisted from commit-recon-report")

	// Verify severity distribution
	sevCounts := map[string]int{}
	for _, f := range dbFindings {
		sevCounts[f.Severity]++
	}
	assert.True(t, sevCounts["high"] > 0, "should have high severity findings")
	assert.True(t, sevCounts["medium"] > 0, "should have medium severity findings")

	// Verify dedup: import the same data again
	findings2 := archon.BuildFindings(result.RawFindings, auditID, agentRun.UUID, database.DefaultProjectUUID, result.RepoName)
	dupes := 0
	for _, f := range findings2 {
		_ = repo.SaveFindingDirect(ctx, f)
		if f.ID == 0 {
			dupes++
		}
	}
	assert.Equal(t, len(findings2), dupes, "all should be duplicates on second import")

	// Export findings to JSONL
	exportPath := filepath.Join(exportDir(), "archon-harbor-findings.jsonl")
	exportFindings(t, db, exportPath)

	// Verify exported file
	exportData, err := os.ReadFile(exportPath)
	require.NoError(t, err)
	assert.NotEmpty(t, exportData)

	// Parse back and verify round-trip
	lines := splitJSONLLines(exportData)
	assert.Equal(t, saved, len(lines), "exported line count should match saved count")

	// Verify first finding round-trips
	var envelope struct {
		Type string           `json:"type"`
		Data database.Finding `json:"data"`
	}
	err = json.Unmarshal(lines[0], &envelope)
	require.NoError(t, err)
	assert.Equal(t, "finding", envelope.Type)
	assert.Equal(t, database.FindingSourceArchon, envelope.Data.FindingSource)
	assert.Equal(t, database.ModuleTypeWhitebox, envelope.Data.ModuleType)

	// Export agent runs to JSONL
	exportRunsPath := filepath.Join(exportDir(), "archon-harbor-agent-runs.jsonl")
	exportAgentRuns(t, db, exportRunsPath)

	runsData, err := os.ReadFile(exportRunsPath)
	require.NoError(t, err)
	runLines := splitJSONLLines(runsData)
	assert.Equal(t, 1, len(runLines), "should export exactly 1 agent run")
}

func TestArchonImport_AllDatasets(t *testing.T) {
	datasets := []string{
		"archon-output-harbor",
		"archon-ouput-grafana",
		"archon-output-kong",
		"archon-output-redash",
	}

	for _, ds := range datasets {
		t.Run(ds, func(t *testing.T) {
			dir := filepath.Join(archonTestdataDir(), ds)
			if _, err := os.Stat(filepath.Join(dir, "audit-state.json")); os.IsNotExist(err) {
				t.Skipf("no audit-state.json in %s", ds)
			}

			result, err := archon.ParseAuditFolder(dir)
			require.NoError(t, err)
			require.NotNil(t, result.State)

			_, repo := setupTestDB(t)
			ctx := context.Background()

			agentRun := archon.BuildAgentRun(result.State, dir, database.DefaultProjectUUID)
			err = repo.CreateAgentRun(ctx, agentRun)
			require.NoError(t, err)

			auditID := result.State.Audits[0].AuditID
			findings := archon.BuildFindings(result.RawFindings, auditID, agentRun.UUID, database.DefaultProjectUUID, result.RepoName)

			saved := 0
			for _, f := range findings {
				err := repo.SaveFindingDirect(ctx, f)
				require.NoError(t, err)
				if f.ID > 0 {
					saved++
				}
			}

			t.Logf("%s: %d findings parsed, %d saved", ds, len(result.RawFindings), saved)
			assert.True(t, saved > 0 || len(result.RawFindings) == 0,
				"should save findings if any were parsed")
		})
	}
}

// --- helpers ---

type exportEnvelope struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func exportFindings(t *testing.T, db *database.DB, outPath string) {
	t.Helper()
	ctx := context.Background()

	var findings []*database.Finding
	err := db.NewSelect().Model(&findings).OrderExpr("module_id ASC").Scan(ctx)
	require.NoError(t, err)

	f, err := os.Create(outPath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, finding := range findings {
		err := enc.Encode(exportEnvelope{Type: "finding", Data: finding})
		require.NoError(t, err)
	}
}

func exportAgentRuns(t *testing.T, db *database.DB, outPath string) {
	t.Helper()
	ctx := context.Background()

	var runs []*database.AgentRun
	err := db.NewSelect().Model(&runs).OrderExpr("created_at DESC").Scan(ctx)
	require.NoError(t, err)

	f, err := os.Create(outPath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, run := range runs {
		err := enc.Encode(exportEnvelope{Type: "agent_run", Data: run})
		require.NoError(t, err)
	}
}

func splitJSONLLines(data []byte) [][]byte {
	var lines [][]byte
	for _, line := range splitBytes(data, '\n') {
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

func splitBytes(data []byte, sep byte) [][]byte {
	var result [][]byte
	start := 0
	for i, b := range data {
		if b == sep {
			result = append(result, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		result = append(result, data[start:])
	}
	return result
}
