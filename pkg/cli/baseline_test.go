package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func baselineEvent(module, path string, sev severity.Severity) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: module,
		Info:     output.Info{Name: module, Description: "d-" + module + path, Severity: sev},
		Host:     "app.test", URL: "https://app.test" + path, Matched: "https://app.test" + path,
		Request: "GET " + path + " HTTP/1.1\r\nHost: app.test\r\n\r\n",
	}
}

// writeBaselineStore saves events into a standalone SQLite store (a previous
// run's -S --format sqlite export) and returns its path.
func writeBaselineStore(t *testing.T, scanUUID string, events ...*output.ResultEvent) (string, *database.Repository) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "prev.sqlite")
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.EnsureSchemaReady(context.Background()))
	repo := database.NewRepository(db)
	for _, ev := range events {
		require.NoError(t, repo.SaveFinding(context.Background(), ev, nil, scanUUID, database.DefaultProjectUUID))
	}
	return path, repo
}

// TestBaselineAndIgnoreGate is RUN-4: with --baseline only findings not in the
// previous run count toward --fail-on; ignore-file hashes never count (expired
// entries do); the -j counts say new/unchanged/fixed/ignored.
func TestBaselineAndIgnoreGate(t *testing.T) {
	old := baselineEvent("sqli", "/a", severity.High)
	gone := baselineEvent("xss", "/b", severity.High)
	path, _ := writeBaselineStore(t, "prev", old, gone)

	ignored := baselineEvent("lfi", "/c", severity.Critical)
	fresh := baselineEvent("ssrf", "/d", severity.High)
	ignoreFile := filepath.Join(t.TempDir(), "ignore.yaml")
	require.NoError(t, os.WriteFile(ignoreFile, []byte("ignore:\n  - hash: "+ignored.ID()+"\n    reason: accepted\n  - hash: "+fresh.ID()+"\n    reason: stale\n    expires: 2001-01-01\n"), 0o644))

	defer func(b, i, f string) { scanBaselinePath, scanIgnoreFile, scanFailOn = b, i, f }(scanBaselinePath, scanIgnoreFile, scanFailOn)
	scanBaselinePath, scanIgnoreFile, scanFailOn = path, ignoreFile, "high"
	require.NoError(t, resetFailOnGate())

	failOnGateFromEvents([]*output.ResultEvent{old, ignored, fresh}, true)
	require.True(t, failOnGateTriggered, "the new high finding trips the gate")
	require.Equal(t, &baselineCounts{New: 1, Unchanged: 1, Fixed: 1, Ignored: 1}, baselineDocument())

	require.NoError(t, resetFailOnGate())
	failOnGateFromEvents([]*output.ResultEvent{old, ignored}, true)
	require.False(t, failOnGateTriggered, "unchanged and ignored findings never trip the gate")
}

// TestScanDiffAgainstBaselineFile: scan diff takes a previous run's export as
// its base.
func TestScanDiffAgainstBaselineFile(t *testing.T) {
	old := baselineEvent("sqli", "/a", severity.High)
	gone := baselineEvent("xss", "/b", severity.High)
	path, _ := writeBaselineStore(t, "prev", old, gone)

	fresh := baselineEvent("ssrf", "/d", severity.High)
	_, repo := writeBaselineStore(t, "head", old, fresh)
	ctx := context.Background()
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: "head", ProjectUUID: database.DefaultProjectUUID, Status: "running"}))
	require.NoError(t, repo.CompleteScanWithOutcome(ctx, "head", "", database.ScanCompletion{Completeness: database.CompletenessComplete}))
	head, err := repo.GetScanByUUID(ctx, "head")
	require.NoError(t, err)

	require.True(t, isBaselineFileRef(path))
	require.False(t, isBaselineFileRef("latest"))
	diff, err := diffAgainstBaselineFile(ctx, repo, database.DefaultProjectUUID, path, head)
	require.NoError(t, err)
	require.Equal(t, 1, diff.Counts[database.DiffNew])
	require.Equal(t, 1, diff.Counts[database.DiffUnchanged])
	require.Equal(t, 1, diff.Counts[database.DiffFixed])

	applyIgnoreToDiff(diff, ignoreSet{fresh.ID(): {Hash: fresh.ID()}})
	require.Equal(t, 0, diff.Counts[database.DiffNew])
	require.Equal(t, 1, diff.Counts[diffClassIgnored])
}

func TestLoadIgnoreFileForms(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "list.yaml")
	require.NoError(t, os.WriteFile(list, []byte("- hash: ABCDEF0123456789\n  reason: r\n"), 0o644))
	set, err := loadIgnoreFile(list, time.Now())
	require.NoError(t, err)
	require.True(t, set.matches("abcdef0123456789ffff"), "a listed 12+ char prefix matches")

	bad := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("- reason: no hash\n"), 0o644))
	_, err = loadIgnoreFile(bad, time.Now())
	require.Error(t, err)

	_, err = loadIgnoreFile(filepath.Join(dir, "missing.yaml"), time.Now())
	require.Error(t, err, "an explicit --ignore-file that does not exist is an error")
}
