package cli

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// scan.finished carries what a stream-only consumer otherwise has to read off
// the -j document or the store: per-class scope drops, the controls the crawl
// refused to click, the interactsh sessions left open, how far a curtailed
// phase got, and the exit status the invocation ends with.
func TestScanFinishedCarriesStreamOnlyFacts(t *testing.T) {
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "finished.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	require.NoError(t, db.EnsureSchemaReady(ctx))
	repo := database.NewRepository(db)

	total := int64(400)
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{
		UUID: "scan-finished", ProjectUUID: database.DefaultProjectUUID, Status: "completed",
		Completeness: database.CompletenessPartial, StartedAt: time.Now(),
		PhaseOutcomes: []database.PhaseOutcome{
			{Phase: "spidering", State: database.PhasePartial, Reasons: []string{database.ReasonPhaseDeadline},
				Progress: &database.PhaseProgress{Done: 120, Total: &total, Unit: "targets"},
				Counts:   map[string]int64{database.ScopeDroppedCountPrefix + "host": 7, database.CountSkippedControls: 3},
				SkippedControls: []scanevents.SkippedControl{
					{Label: "Delete account", Selector: "/html/body/button[1]", URL: "https://app.test/settings", Reason: "deny_click", Match: "Delete"},
				}},
			{Phase: "discovery", State: database.PhaseCompleted,
				Counts: map[string]int64{database.ScopeDroppedCountPrefix + "host": 2, database.ScopeDroppedCountPrefix + "static_file": 5}},
		},
	}))
	require.NoError(t, repo.SaveOASTSession(ctx, &database.OASTSession{
		ProjectUUID: database.DefaultProjectUUID, ScanUUID: "scan-finished",
		ServerURL: "https://oast.example", CorrelationID: "corr1", SecretKey: "s3cret",
	}))

	ev := &scanevents.Event{Type: scanevents.TypeScanFinished, Status: scanevents.StatusCompleted}
	scanFinishTotals(db, ev, &types.Options{ScanUUID: "scan-finished", ProjectUUID: database.DefaultProjectUUID})

	require.Equal(t, map[string]int64{"host": 9, "static_file": 5}, ev.ScopeDropped)
	require.NotNil(t, ev.SkippedControls)
	require.EqualValues(t, 3, ev.SkippedControls.Count)
	require.Len(t, ev.SkippedControls.Sample, 1)
	require.Equal(t, "Delete account", ev.SkippedControls.Sample[0].Label)
	require.Len(t, ev.OASTSessionsKept, 1)
	require.Equal(t, "https://oast.example", ev.OASTSessionsKept[0].Server)
	require.NotZero(t, ev.OASTSessionsKept[0].ID)

	var deadline *scanevents.Caveat
	for i := range ev.Caveats {
		if ev.Caveats[i].Code == database.ReasonPhaseDeadline {
			deadline = &ev.Caveats[i]
		}
	}
	require.NotNil(t, deadline, "caveats = %+v", ev.Caveats)
	require.NotNil(t, deadline.Done)
	require.NotNil(t, deadline.Total)
	require.EqualValues(t, 120, *deadline.Done)
	require.EqualValues(t, 400, *deadline.Total)
	require.Equal(t, "targets", deadline.Unit)

	// The wire form: the key names a consumer reads, and no session key
	// material.
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	for _, k := range []string{"scope_dropped", "skipped_controls", "oast_sessions_kept", "caveats"} {
		require.Contains(t, wire, k)
	}
	require.NotContains(t, string(raw), "s3cret")
}

func TestApplyExitOutcome(t *testing.T) {
	ev := &scanevents.Event{}
	applyExitOutcome(ev, nil)
	require.NotNil(t, ev.ExitCode)
	require.Equal(t, 0, *ev.ExitCode)
	require.Empty(t, ev.ErrorCode)

	ev = &scanevents.Event{}
	applyExitOutcome(ev, errors.New("boom"))
	require.Equal(t, ExitError, *ev.ExitCode)
	require.Equal(t, string(apicontract.CodeFailed), ev.ErrorCode)

	ev = &scanevents.Event{}
	applyExitOutcome(ev, incompleteErrorf(apicontract.CodePartial, "partial"))
	require.Equal(t, ExitIncomplete, *ev.ExitCode)
	require.Equal(t, string(apicontract.CodePartial), ev.ErrorCode)

	ev = &scanevents.Event{}
	applyExitOutcome(ev, gateError{err: errors.New("--fail-on high")})
	require.Equal(t, ExitFailOnGate, *ev.ExitCode)
	require.Equal(t, string(apicontract.CodeGateTripped), ev.ErrorCode)
}

// The -j scan document carries skipped_controls in the same shape as
// scan.finished: exact count, bounded sample by name.
func TestScanDocumentSkippedControls(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true
	b := newScanDocBuilder("scan")
	b.AddDirect(&scanResult{Target: "http://a.example/", ScanUUID: "u", Reachable: true, Persisted: true}, nil)
	b.scans[0].phases = []database.PhaseOutcome{{
		Phase: "spidering", State: database.PhaseCompleted,
		Counts:          map[string]int64{database.CountSkippedControls: 4},
		SkippedControls: []scanevents.SkippedControl{{Label: "Pay now", Reason: "deny_click", Match: "Pay now"}},
	}}
	raw, err := encodeAgentJSON(b.envelope())
	require.NoError(t, err)
	var doc struct {
		SkippedControls struct {
			Count  int64                       `json:"count"`
			Sample []scanevents.SkippedControl `json:"sample"`
		} `json:"skipped_controls"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.EqualValues(t, 4, doc.SkippedControls.Count)
	require.Len(t, doc.SkippedControls.Sample, 1)
	require.Equal(t, "Pay now", doc.SkippedControls.Sample[0].Label)
}
