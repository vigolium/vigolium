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

	"github.com/vigolium/vigolium/pkg/audit"
	"github.com/vigolium/vigolium/pkg/database"
)

func auditTestdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata", "vigolium-audit-data")
}

func exportDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata", "vigolium-export")
}

func TestAuditDriverImport_HarborFullPipeline(t *testing.T) {
	harborDir := filepath.Join(auditTestdataDir(), "audit-output-harbor")
	if _, err := os.Stat(filepath.Join(harborDir, "audit-state.json")); os.IsNotExist(err) {
		t.Skipf("harbor audit fixture not present in this checkout: %s", harborDir)
	}

	// Parse the audit output folder
	result, err := audit.ParseFolder(harborDir)
	require.NoError(t, err)
	require.NotNil(t, result.State)
	require.NotEmpty(t, result.RawFindings)

	// Set up in-memory DB
	db, repo := setupTestDB(t)
	ctx := context.Background()

	// Build and create AgenticScan
	agenticScan := audit.BuildAgenticScan(result.State, harborDir, database.DefaultProjectUUID)
	require.NotEmpty(t, agenticScan.UUID)
	err = repo.CreateAgenticScan(ctx, agenticScan)
	require.NoError(t, err)

	// Verify AgenticScan was stored
	storedRun, err := repo.GetAgenticScan(ctx, agenticScan.UUID)
	require.NoError(t, err)
	assert.Equal(t, "audit", storedRun.Mode)
	assert.Equal(t, "vigolium-audit", storedRun.AgentName)
	assert.Equal(t, "completed", storedRun.Status)
	assert.Equal(t, "audit", storedRun.InputType)
	assert.Contains(t, storedRun.InputRaw, "commit:")
	assert.Contains(t, storedRun.InputRaw, "branch:audit")
	assert.Len(t, storedRun.PhasesRun, 11)
	assert.Equal(t, 47, storedRun.FindingCount)
	assert.NotEmpty(t, storedRun.ResultJSON)
	assert.True(t, storedRun.DurationMs > 0)

	// Build and save findings
	auditID := result.State.Audits[0].AuditID
	findings := audit.BuildFindings(result.RawFindings, auditID, agenticScan.UUID, database.DefaultProjectUUID, result.RepoName)
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
		if f.ModuleID == "audit:p7-001" {
			p7001 = f
			break
		}
	}
	require.NotNil(t, p7001, "should find audit:p7-001 in DB")
	assert.Equal(t, "Open Redirect via Unvalidated postURI in Auth-Proxy Controller", p7001.ModuleName)
	assert.Equal(t, "high", p7001.Severity)
	assert.Equal(t, "firm", p7001.Confidence)
	assert.Equal(t, database.ModuleTypeWhitebox, p7001.ModuleType)
	assert.Equal(t, database.FindingSourceAudit, p7001.FindingSource)
	assert.Equal(t, "open-redirect-authproxy", p7001.ModuleShort)
	assert.Equal(t, "CWE-601", p7001.CWEID)
	assert.Equal(t, agenticScan.UUID, p7001.AgenticScanUUID)
	assert.Contains(t, p7001.Tags, "audit")
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
	findings2 := audit.BuildFindings(result.RawFindings, auditID, agenticScan.UUID, database.DefaultProjectUUID, result.RepoName)
	dupes := 0
	for _, f := range findings2 {
		_ = repo.SaveFindingDirect(ctx, f)
		if f.ID == 0 {
			dupes++
		}
	}
	assert.Equal(t, len(findings2), dupes, "all should be duplicates on second import")

	// Export findings to JSONL
	exportPath := filepath.Join(exportDir(), "audit-harbor-findings.jsonl")
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
	assert.Equal(t, database.FindingSourceAudit, envelope.Data.FindingSource)
	assert.Equal(t, database.ModuleTypeWhitebox, envelope.Data.ModuleType)

	// Export agent runs to JSONL
	exportRunsPath := filepath.Join(exportDir(), "audit-harbor-agent-runs.jsonl")
	exportAgenticScans(t, db, exportRunsPath)

	runsData, err := os.ReadFile(exportRunsPath)
	require.NoError(t, err)
	runLines := splitJSONLLines(runsData)
	assert.Equal(t, 1, len(runLines), "should export exactly 1 agent run")
}

func TestAuditDriverImport_AllDatasets(t *testing.T) {
	datasets := []string{
		"audit-output-harbor",
		"audit-output-grafana",
		"audit-output-kong",
		"audit-output-redash",
	}

	for _, ds := range datasets {
		t.Run(ds, func(t *testing.T) {
			dir := filepath.Join(auditTestdataDir(), ds)
			if _, err := os.Stat(filepath.Join(dir, "audit-state.json")); os.IsNotExist(err) {
				t.Skipf("no audit-state.json in %s", ds)
			}

			result, err := audit.ParseFolder(dir)
			require.NoError(t, err)
			require.NotNil(t, result.State)

			_, repo := setupTestDB(t)
			ctx := context.Background()

			agenticScan := audit.BuildAgenticScan(result.State, dir, database.DefaultProjectUUID)
			err = repo.CreateAgenticScan(ctx, agenticScan)
			require.NoError(t, err)

			auditID := result.State.Audits[0].AuditID
			findings := audit.BuildFindings(result.RawFindings, auditID, agenticScan.UUID, database.DefaultProjectUUID, result.RepoName)

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

func exportAgenticScans(t *testing.T, db *database.DB, outPath string) {
	t.Helper()
	ctx := context.Background()

	var runs []*database.AgenticScan
	err := db.NewSelect().Model(&runs).OrderExpr("created_at DESC").Scan(ctx)
	require.NoError(t, err)

	f, err := os.Create(outPath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, run := range runs {
		err := enc.Encode(exportEnvelope{Type: "agentic_scan", Data: run})
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

// --- e2e tests for report.md, poc, metadata enrichment ---

func TestAuditDriverImport_OllamaReportAndPoC(t *testing.T) {
	ollamaDir := filepath.Join(auditTestdataDir(), "ollama-audit")
	if _, err := os.Stat(filepath.Join(ollamaDir, "audit-state.json")); os.IsNotExist(err) {
		t.Skipf("ollama-audit fixture not present: %s", ollamaDir)
	}

	result, err := audit.ParseFolder(ollamaDir)
	require.NoError(t, err)
	require.NotNil(t, result.State)
	require.NotEmpty(t, result.RawFindings)

	db, repo := setupTestDB(t)
	ctx := context.Background()

	agenticScan := audit.BuildAgenticScan(result.State, ollamaDir, database.DefaultProjectUUID)
	require.NoError(t, repo.CreateAgenticScan(ctx, agenticScan))

	auditID := result.State.Audits[0].AuditID
	findings := audit.BuildFindings(result.RawFindings, auditID, agenticScan.UUID, database.DefaultProjectUUID, result.RepoName)
	require.NotEmpty(t, findings)

	for _, f := range findings {
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}

	// Retrieve all findings from DB.
	var dbFindings []*database.Finding
	err = db.NewSelect().Model(&dbFindings).
		Where("project_uuid = ?", database.DefaultProjectUUID).
		OrderExpr("module_id ASC").
		Scan(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, dbFindings)

	// --- C1: has report.md, poc.py, metadata.json (variant of H6) ---
	var c1 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleID == "audit:c1" {
			c1 = f
			break
		}
	}
	require.NotNil(t, c1, "should find audit:c1")
	assert.Equal(t, "critical", c1.Severity)
	assert.Equal(t, database.FindingSourceAudit, c1.FindingSource)

	// report.md should be the body source (contains structured report content).
	assert.Contains(t, c1.Description, "IsAutoAllowed", "body should contain report.md content")

	// PoC content should be embedded in the description.
	assert.Contains(t, c1.Description, "## Proof of Concept (`poc.py`)", "poc should be in description")
	assert.Contains(t, c1.Description, "```py", "poc should have python code fence")
	assert.Contains(t, c1.Description, "AUTO_ALLOW_PREFIXES", "poc.py content should be present")

	// Tags should include poc-available and variant info from metadata.json.
	assert.Contains(t, c1.Tags, "poc-available")
	assert.Contains(t, c1.Tags, "variant-of:H6")

	// --- H1: has report.md, poc.py, adversarial-review.md ---
	var h1 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleID == "audit:h1" {
			h1 = f
			break
		}
	}
	require.NotNil(t, h1, "should find audit:h1")
	assert.Equal(t, "high", h1.Severity)
	assert.Contains(t, h1.Description, "## Proof of Concept (`poc.py`)")
	assert.Contains(t, h1.Tags, "poc-available")

	// --- H5: has report.md, poc.sh (bash PoC) ---
	var h5 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleID == "audit:h5" {
			h5 = f
			break
		}
	}
	require.NotNil(t, h5, "should find audit:h5")
	assert.Contains(t, h5.Description, "## Proof of Concept (`poc.sh`)")
	assert.Contains(t, h5.Description, "```sh", "poc should have bash code fence")

	// --- H2: has poc.go (Go PoC) ---
	var h2 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleID == "audit:h2" {
			h2 = f
			break
		}
	}
	require.NotNil(t, h2, "should find audit:h2")
	assert.Contains(t, h2.Description, "## Proof of Concept (`poc.go`)")
	assert.Contains(t, h2.Description, "```go", "poc should have go code fence")

	// --- M1: has report.md + metadata.json but NO poc file ---
	var m1 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleID == "audit:m1" {
			m1 = f
			break
		}
	}
	require.NotNil(t, m1, "should find audit:m1")
	assert.NotContains(t, m1.Description, "## Proof of Concept (`poc.", "no poc file means no embedded poc code block")
	assert.NotContains(t, m1.Tags, "poc-available")

	// --- M10: has NO poc file ---
	var m10 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleID == "audit:m10" {
			m10 = f
			break
		}
	}
	require.NotNil(t, m10, "should find audit:m10")
	assert.NotContains(t, m10.Description, "## Proof of Concept (`poc.", "no poc file means no embedded poc code block")
	assert.NotContains(t, m10.Tags, "poc-available")

	// Verify remediation is populated for findings with ## Fix sections.
	findingsWithRemediation := 0
	for _, f := range dbFindings {
		if f.Remediation != "" {
			findingsWithRemediation++
		}
	}
	t.Logf("ollama-audit: %d findings, %d with remediation", len(dbFindings), findingsWithRemediation)
}

func TestAuditDriverImport_GrafanaReportAndPoC(t *testing.T) {
	grafanaDir := filepath.Join(auditTestdataDir(), "grafana-archon")
	if _, err := os.Stat(filepath.Join(grafanaDir, "audit-state.json")); os.IsNotExist(err) {
		t.Skipf("grafana-audit fixture not present: %s", grafanaDir)
	}

	result, err := audit.ParseFolder(grafanaDir)
	require.NoError(t, err)
	require.NotNil(t, result.State)
	require.NotEmpty(t, result.RawFindings)

	db, repo := setupTestDB(t)
	ctx := context.Background()

	agenticScan := audit.BuildAgenticScan(result.State, grafanaDir, database.DefaultProjectUUID)
	require.NoError(t, repo.CreateAgenticScan(ctx, agenticScan))

	auditID := result.State.Audits[0].AuditID
	findings := audit.BuildFindings(result.RawFindings, auditID, agenticScan.UUID, database.DefaultProjectUUID, result.RepoName)
	require.NotEmpty(t, findings)

	for _, f := range findings {
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}

	var dbFindings []*database.Finding
	err = db.NewSelect().Model(&dbFindings).
		Where("project_uuid = ?", database.DefaultProjectUUID).
		OrderExpr("module_id ASC").
		Scan(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, dbFindings)

	// --- H3 (pubdash-credential-exposure): bold-header format report, poc.sh ---
	// H2 also has slug pubdash-credential-exposure but no report/poc; use module_id.
	var h3 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleID == "audit:h3" && f.ModuleShort == "pubdash-credential-exposure" {
			h3 = f
			break
		}
	}
	require.NotNil(t, h3, "should find audit:h3 pubdash-credential-exposure")

	// Title should come from report.md's H1 heading, not draft.md.
	assert.Contains(t, h3.ModuleName, "Credential", "title from report.md H1")

	// PoC content (bash script) should be in description.
	assert.Contains(t, h3.Description, "## Proof of Concept (`poc.sh`)")
	assert.Contains(t, h3.Description, "```sh")
	assert.Contains(t, h3.Description, "#!/usr/bin/env bash")
	assert.Contains(t, h3.Tags, "poc-available")

	// PoC-Status from report.md header.
	assert.Contains(t, h3.Tags, "poc-executed")

	// Remediation from ## Fix section.
	assert.NotEmpty(t, h3.Remediation)
	assert.Contains(t, h3.Remediation, "IsPublicDashboardView()")

	// --- H6 (proxy-auth-empty-allowlist): plain-kv format report, no poc file ---
	var h6 *database.Finding
	for _, f := range dbFindings {
		if f.ModuleShort == "proxy-auth-empty-allowlist" {
			h6 = f
			break
		}
	}
	require.NotNil(t, h6, "should find proxy-auth-empty-allowlist")
	assert.Equal(t, "high", h6.Severity)
	assert.NotContains(t, h6.Description, "## Proof of Concept (`poc.", "no poc file means no embedded poc code block")
	assert.NotContains(t, h6.Tags, "poc-available")

	// --- Findings without report.md (evidence-only dirs like H1-storewrapper-watch-unfiltered) ---
	// These should still be parsed (from evidence dir presence) or skipped gracefully.
	t.Logf("grafana-archon: %d findings imported to DB", len(dbFindings))

	// Verify dedup works with the enriched data.
	findings2 := audit.BuildFindings(result.RawFindings, auditID, agenticScan.UUID, database.DefaultProjectUUID, result.RepoName)
	dupes := 0
	for _, f := range findings2 {
		_ = repo.SaveFindingDirect(ctx, f)
		if f.ID == 0 {
			dupes++
		}
	}
	assert.Equal(t, len(findings2), dupes, "all should be duplicates on second import")
}

func TestAuditDriverImport_PoCContentRoundTrip(t *testing.T) {
	ollamaDir := filepath.Join(auditTestdataDir(), "ollama-audit")
	if _, err := os.Stat(filepath.Join(ollamaDir, "audit-state.json")); os.IsNotExist(err) {
		t.Skipf("ollama-audit fixture not present: %s", ollamaDir)
	}

	result, err := audit.ParseFolder(ollamaDir)
	require.NoError(t, err)

	db, repo := setupTestDB(t)
	ctx := context.Background()

	agenticScan := audit.BuildAgenticScan(result.State, ollamaDir, database.DefaultProjectUUID)
	require.NoError(t, repo.CreateAgenticScan(ctx, agenticScan))

	auditID := result.State.Audits[0].AuditID
	findings := audit.BuildFindings(result.RawFindings, auditID, agenticScan.UUID, database.DefaultProjectUUID, result.RepoName)
	for _, f := range findings {
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}

	// Export to JSONL.
	exportPath := filepath.Join(t.TempDir(), "findings.jsonl")
	exportFindings(t, db, exportPath)

	exportData, err := os.ReadFile(exportPath)
	require.NoError(t, err)

	// Parse back and verify PoC content survives the round-trip.
	lines := splitJSONLLines(exportData)
	require.NotEmpty(t, lines)

	foundPoCInExport := false
	for _, line := range lines {
		var envelope struct {
			Type string           `json:"type"`
			Data database.Finding `json:"data"`
		}
		err := json.Unmarshal(line, &envelope)
		require.NoError(t, err)

		if envelope.Data.ModuleID == "audit:c1" {
			assert.Contains(t, envelope.Data.Description, "## Proof of Concept (`poc.py`)")
			assert.Contains(t, envelope.Data.Description, "AUTO_ALLOW_PREFIXES")
			foundPoCInExport = true
			break
		}
	}
	assert.True(t, foundPoCInExport, "C1 with PoC content should be in the exported JSONL")
}
