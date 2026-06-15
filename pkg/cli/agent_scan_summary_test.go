package cli

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

// TestAgentScanSummaryTreeAggregation verifies that emitAgentScanJSONSummary
// rolls up findings across the whole agentic-scan tree (parent + nested driver
// children) and that resolveAgenticScanTree discovers the children.
func TestAgentScanSummaryTreeAggregation(t *testing.T) {
	db := newExportTestDB(t)
	ctx := context.Background()
	project := database.DefaultProjectUUID
	parent := "parent-scan-uuid"
	child := "child-scan-uuid"

	for _, sc := range []database.AgenticScan{
		{UUID: parent, ProjectUUID: project, Mode: "audit", AgentName: "audit"},
		{UUID: child, ProjectUUID: project, Mode: "audit", AgentName: "audit", ParentAgenticScanUUID: parent},
	} {
		s := sc
		_, err := db.NewInsert().Model(&s).Exec(ctx)
		require.NoError(t, err)
	}

	repo := database.NewRepository(db)
	require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID: project, AgenticScanUUID: parent, ModuleID: "m1", ModuleName: "M1",
		Severity: "critical", Confidence: "firm", FindingHash: "h1",
	}))
	require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID: project, AgenticScanUUID: child, ModuleID: "m2", ModuleName: "M2",
		Severity: "high", Confidence: "firm", FindingHash: "h2",
	}))

	// Tree expansion finds the child run.
	tree := resolveAgenticScanTree(ctx, db, parent)
	require.ElementsMatch(t, []string{parent, child}, tree)

	prevJSON := globalJSON
	globalJSON = true
	t.Cleanup(func() { globalJSON = prevJSON })

	out := captureStdout(t, func() {
		emitAgentScanJSONSummary(repo, project, parent, "completed", "/tmp/session")
	})

	var got struct {
		AgenticScanUUID string           `json:"agentic_scan_uuid"`
		Status          string           `json:"status"`
		SessionDir      string           `json:"session_dir"`
		TotalFindings   int64            `json:"total_findings"`
		Counts          map[string]int64 `json:"counts_by_severity"`
		Top             []map[string]any `json:"top_findings"`
		Query           string           `json:"query"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Equal(t, parent, got.AgenticScanUUID)
	require.Equal(t, "completed", got.Status)
	require.Equal(t, "/tmp/session", got.SessionDir)
	require.Equal(t, int64(2), got.TotalFindings, "should aggregate parent + child findings")
	require.Equal(t, int64(1), got.Counts["critical"])
	require.Equal(t, int64(1), got.Counts["high"])
	require.Len(t, got.Top, 2)
	require.Equal(t, "critical", got.Top[0]["severity"], "top findings ranked by severity desc")
	require.Contains(t, got.Query, parent)
}

// TestAgentScanSummaryNoopWithoutJSON confirms the summary is silent unless
// --json is set, so default console output is unchanged.
func TestAgentScanSummaryNoopWithoutJSON(t *testing.T) {
	db := newExportTestDB(t)
	repo := database.NewRepository(db)

	prevJSON := globalJSON
	globalJSON = false
	t.Cleanup(func() { globalJSON = prevJSON })

	out := captureStdout(t, func() {
		emitAgentScanJSONSummary(repo, database.DefaultProjectUUID, "some-uuid", "completed", "/x")
	})
	require.Empty(t, out, "no stdout output expected without --json")
}
