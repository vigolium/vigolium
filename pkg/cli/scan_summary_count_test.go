package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// TestSummaryFindingCountsIsTheScansOwn: the completion summary's "N issues
// found" is the scan's count from repository.ScanFindingTotal — the helper the
// runner's "Scan finished … findings: N" banner prints — not the project-wide
// count over the in-scope hosts it used to be, which disagreed with the banner
// on any project that had earlier scans of the same host.
func TestSummaryFindingCountsIsTheScansOwn(t *testing.T) {
	ctx := context.Background()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "summary.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, db.CreateSchema(ctx))
	repo := database.NewRepository(db)

	project := database.DefaultProjectUUID
	const thisScan = "33333333-3333-3333-3333-333333333333"
	const earlier = "44444444-4444-4444-4444-444444444444"
	for _, u := range []string{thisScan, earlier} {
		require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: u, ProjectUUID: project, Status: "running", StartedAt: time.Now()}))
	}
	save := func(scanUUID, hash, sev string) {
		require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
			ProjectUUID: project, ScanUUID: scanUUID, ModuleID: "m", ModuleName: "M",
			Severity: sev, Confidence: "firm", FindingHash: hash,
			URL: "http://a.test/", Hostname: "a.test",
		}))
	}
	save(thisScan, "h1", "high")
	save(thisScan, "h2", "low")
	save(earlier, "h3", "critical")
	hosts := []database.HostTarget{{Hostname: "a.test"}}

	total, counts, err := summaryFindingCounts(ctx, repo, project, thisScan, hosts)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.EqualValues(t, 1, counts["high"])
	require.EqualValues(t, 1, counts["low"])
	require.Zero(t, counts["critical"], "another scan's finding leaked into this scan's summary")

	bannerTotal, _, err := repo.ScanFindingTotal(ctx, thisScan)
	require.NoError(t, err)
	require.EqualValues(t, bannerTotal, total, "summary and banner disagree")

	// No scan id: the host-scoped project count, as before.
	total, _, err = summaryFindingCounts(ctx, repo, project, "", hosts)
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
}

// The banner's estimate line carries the rough duration range.
func TestEstimateBannerLineDuration(t *testing.T) {
	plan := &scanplan.Plan{Estimate: scanplan.Estimate{Low: 10, High: 100, Confidence: scanplan.ConfidenceRough,
		DurationMS: &scanplan.DurationEstimate{Low: 90_000, High: 900_000, Confidence: scanplan.ConfidenceRough}}}
	line := terminal.StripANSI(estimateBannerLine(plan))
	assert.Contains(t, line, "~2m-15m (rough)")
	assert.Equal(t, "45s", formatDurationRange(44_600, 45_000))
	assert.Equal(t, "1h05m", formatDurationRange(3_900_000, 3_900_000))
}
