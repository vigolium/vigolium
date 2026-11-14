package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestFailOnPartial is RES-3: a scan whose phase deadline fired (partial
// coverage) exits 5 under --fail-on-partial, and --fail-on implies it; a gate
// trip (4) and an error (1) outrank it.
func TestFailOnPartial(t *testing.T) {
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "p.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	require.NoError(t, db.EnsureSchemaReady(ctx))
	repo := database.NewRepository(db)
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: "s-partial", ProjectUUID: database.DefaultProjectUUID, Status: "running"}))
	require.NoError(t, repo.CompleteScanWithOutcome(ctx, "s-partial", "", database.ScanCompletion{
		Completeness: database.CompletenessPartial,
		Phases: []database.PhaseOutcome{{
			Phase: "dynamic-assessment", State: database.PhasePartial, Reasons: []string{database.ReasonPhaseDeadline},
		}},
	}))

	defer func(fo string, fop bool) { scanFailOn, scanFailOnPartial = fo, fop }(scanFailOn, scanFailOnPartial)

	run := func(failOn string, partial bool, prior error) int {
		scanFailOn, scanFailOnPartial = failOn, partial
		require.NoError(t, resetFailOnGate())
		evaluatePartialGate(repo, "s-partial")
		return classifyExitCode(withFailOnGate(prior))
	}

	require.Equal(t, ExitSuccess, run("", false, nil), "no gate armed: a partial scan still exits 0")
	require.Equal(t, ExitIncomplete, run("", true, nil), "--fail-on-partial")
	require.Equal(t, ExitIncomplete, run("critical", false, nil), "--fail-on implies --fail-on-partial")
	require.Equal(t, ExitError, run("", true, errors.New("boom")), "an error outranks incomplete")

	scanFailOn, scanFailOnPartial = "info", true
	require.NoError(t, resetFailOnGate())
	evaluatePartialGate(repo, "s-partial")
	markFailOnTriggered(1, true)
	require.Equal(t, ExitFailOnGate, classifyExitCode(withFailOnGate(nil)), "a gate trip outranks incomplete")
}
