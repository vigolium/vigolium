package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanplan"
)

// etaTestPlan: discovery (10m phase ceiling) → dynamic-assessment (30m) →
// known-issue-scan (5m), behind an enabled preflight, plus a disabled phase.
func etaTestPlan() *scanplan.Plan {
	ceiling := func(ms time.Duration) *scanplan.PhaseBudget {
		return &scanplan.PhaseBudget{PhaseCeilingMS: ms.Milliseconds(), Semantics: scanplan.SemanticsPhase, Source: scanplan.SourceDefault}
	}
	return &scanplan.Plan{
		SchemaVersion: 1,
		Strategy:      "balanced",
		Targets:       scanplan.Targets{Seeded: 2, Admitted: 2},
		Phases: []scanplan.Phase{
			{ID: string(runner.PhasePreflight), Enabled: true},
			{ID: "discovery", Enabled: true, Budget: ceiling(10 * time.Minute)},
			{ID: "spidering", Enabled: false, DisabledBy: "strategy"},
			{ID: "dynamic-assessment", Enabled: true, Budget: ceiling(30 * time.Minute)},
			{ID: "known-issue-scan", Enabled: true, Budget: ceiling(5 * time.Minute)},
		},
	}
}

func runningETAView(now time.Time, plan *scanplan.Plan) *scanStatusView {
	total := int64(1000)
	return &scanStatusView{
		ScanUUID:        "u",
		EffectiveStatus: effStatusRunning,
		Phase:           "dynamic-assessment",
		PhasesDone:      []string{"discovery"},
		Progress:        &scanProgressView{Done: 250, Total: &total, Unit: "records"},
		Plan:            plan,
		phaseStarted:    now.Add(-2 * time.Minute),
		startedAt:       now.Add(-10 * time.Minute),
	}
}

func etaMS(p *int64) any {
	if p == nil {
		return nil
	}
	return time.Duration(*p) * time.Millisecond
}

// The ETA reads the stored plan: the current phase's own rate plus the later
// phases at 0.6 of their ceilings, bounded by what the ceilings (and the scan
// budget) leave.
func TestScanETAFromStoredPlan(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

	// 250/1000 in 2m → 6m left in this phase; known-issue-scan adds 0.6×5m = 3m.
	// Upper: 30m−2m of this phase + 5m.
	v := runningETAView(now, etaTestPlan())
	eta := scanETA(v, now)
	assert.Equal(t, 9*time.Minute, etaMS(eta.EstimateMS))
	assert.Equal(t, 33*time.Minute, etaMS(eta.UpperBoundMS))
	assert.Equal(t, "phase_rate+plan_ceilings", eta.Basis)

	// A tighter scan budget wins the upper bound and clamps the estimate.
	v.budgetMS = (15 * time.Minute).Milliseconds() // 10m elapsed → 5m left
	eta = scanETA(v, now)
	assert.Equal(t, 5*time.Minute, etaMS(eta.UpperBoundMS))
	assert.Equal(t, 5*time.Minute, etaMS(eta.EstimateMS))
	assert.Equal(t, "phase_rate+plan_ceilings+scan_budget", eta.Basis)

	// No count for the current phase: no estimate, the bound still stands.
	v = runningETAView(now, etaTestPlan())
	v.Progress = nil
	eta = scanETA(v, now)
	assert.Nil(t, eta.EstimateMS)
	assert.Equal(t, 33*time.Minute, etaMS(eta.UpperBoundMS))
	assert.Equal(t, "plan_ceilings", eta.Basis)

	// A later phase with no ceiling: both figures resting on it are unknown.
	plan := etaTestPlan()
	plan.Phase("known-issue-scan").Budget = nil
	v = runningETAView(now, plan)
	eta = scanETA(v, now)
	assert.Nil(t, eta.EstimateMS)
	assert.Nil(t, eta.UpperBoundMS)
	assert.Equal(t, "unknown", eta.Basis)

	// ...unless the scan budget bounds it.
	v.budgetMS = (40 * time.Minute).Milliseconds()
	eta = scanETA(v, now)
	assert.Nil(t, eta.EstimateMS)
	assert.Equal(t, 30*time.Minute, etaMS(eta.UpperBoundMS))
	assert.Equal(t, "scan_budget", eta.Basis)

	// Between phases (discovery done, nothing running): the rest of the plan.
	v = runningETAView(now, etaTestPlan())
	v.Phase, v.Progress = "", nil
	eta = scanETA(v, now)
	assert.Equal(t, 21*time.Minute, etaMS(eta.EstimateMS)) // 0.6 × (30m + 5m)
	assert.Equal(t, 35*time.Minute, etaMS(eta.UpperBoundMS))
	assert.Equal(t, "plan_ceilings", eta.Basis)

	// The last phase: its own tail, bounded by its remaining ceiling.
	v = runningETAView(now, etaTestPlan())
	v.Phase, v.PhasesDone = "known-issue-scan", []string{"discovery", "dynamic-assessment"}
	eta = scanETA(v, now)
	assert.Equal(t, 3*time.Minute, etaMS(eta.UpperBoundMS)) // 5m ceiling − 2m run
	assert.Equal(t, 3*time.Minute, etaMS(eta.EstimateMS))   // 6m at its rate, clamped to the bound
	assert.Equal(t, "phase_rate+plan_ceilings", eta.Basis)
}

// A per-target budget bounds the phase by budget (+ grace) × admitted targets;
// a per-call one bounds nothing.
func TestPlanPhaseCeiling(t *testing.T) {
	p := &scanplan.Plan{
		Targets: scanplan.Targets{Admitted: 3},
		Phases: []scanplan.Phase{
			{ID: "spidering", Enabled: true, Budget: &scanplan.PhaseBudget{PerTargetMS: 60_000, GraceMS: 5_000, Semantics: scanplan.SemanticsPerTarget}},
			{ID: "external-harvest", Enabled: true, Budget: &scanplan.PhaseBudget{PerTargetMS: 10_000, Semantics: scanplan.SemanticsPerCall}},
			{ID: "discovery", Enabled: true, Budget: &scanplan.PhaseBudget{PerTargetMS: 60_000, PhaseCeilingMS: 120_000, Semantics: scanplan.SemanticsPerTargetCapped}},
		},
	}
	assert.EqualValues(t, 195_000, planPhaseCeilingMS(p, "spidering"))
	assert.EqualValues(t, etaRemainingUnbounded, planPhaseCeilingMS(p, "external-harvest"))
	assert.EqualValues(t, 120_000, planPhaseCeilingMS(p, "discovery"))
	assert.EqualValues(t, etaRemainingUnbounded, planPhaseCeilingMS(p, "nope"))
	p.Targets.Admitted = 0
	assert.EqualValues(t, etaRemainingUnbounded, planPhaseCeilingMS(p, "spidering"))
}

// The status view embeds the row's stored plan, and takes the scan budget and
// the phase order from it when no status.json says otherwise.
func TestScanStatusViewEmbedsStoredPlan(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	stubLiveness(t, now, "here", func(int) bool { return true })
	plan := etaTestPlan()
	plan.Budgets.ScanMaxDurationMS = (time.Hour).Milliseconds()
	raw, err := json.Marshal(plan)
	require.NoError(t, err)
	beat := now.Add(-5 * time.Second)
	row := &database.Scan{UUID: "u", Status: "running", StartedAt: now.Add(-10 * time.Minute), HeartbeatAt: &beat, CurrentPhase: "dynamic-assessment", Plan: raw}
	lv := livenessFromSignals(livenessSignals{heartbeatAt: beat})

	v := buildScanStatusView("u", row, nil, lv, now)
	require.NotNil(t, v.Plan)
	assert.Equal(t, "balanced", v.Plan.Strategy)
	assert.Equal(t, []string{"discovery", "dynamic-assessment", "known-issue-scan"}, v.PhasesPlanned)
	// No progress row-side, so no estimate; the bound is the tighter of the
	// remaining hour (50m) and the plan (30m + 5m, phase start unknown).
	assert.Nil(t, v.ETA.EstimateMS)
	assert.Equal(t, 35*time.Minute, etaMS(v.ETA.UpperBoundMS))

	out, err := json.Marshal(v)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(out, &decoded))
	assert.Contains(t, decoded, "plan")

	// No plan on the row: plan is present and null.
	row.Plan = nil
	out, err = json.Marshal(buildScanStatusView("u", row, nil, lv, now))
	require.NoError(t, err)
	decoded = map[string]any{}
	require.NoError(t, json.Unmarshal(out, &decoded))
	v2, ok := decoded["plan"]
	assert.True(t, ok)
	assert.Nil(t, v2)
}

func newC2bTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	cfg := config.DefaultSettings().Database
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "c2b.sqlite")
	db, err := database.NewDB(&cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.EnsureSchemaReady(context.Background()))
	return database.NewRepository(db)
}

// scan wait's document is the scan document rebuilt from the row: the stored
// plan verbatim, the row's own times (not the waiter's), the row's verdict.
func TestScanWaitDocumentFromRow(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true
	repo := newC2bTestRepo(t)
	ctx := context.Background()

	plan := etaTestPlan()
	plan.ScanUUID = "c2b-row"
	raw, err := json.Marshal(plan)
	require.NoError(t, err)
	started := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: "c2b-row", ProjectUUID: database.DefaultProjectUUID, Status: "running", Target: "https://a.example, https://b.example", StartedAt: started}))
	require.NoError(t, repo.UpdateScanPartial(ctx, &database.Scan{UUID: "c2b-row", Plan: raw}))
	require.NoError(t, repo.CompleteScanWithOutcome(ctx, "c2b-row", "", database.ScanCompletion{Completeness: database.CompletenessPartial, StopReason: database.ReasonScanBudget}))
	row, err := repo.GetScanByUUID(ctx, "c2b-row")
	require.NoError(t, err)

	reader := &scanStatusReader{repo: repo, dbPath: "/tmp/c2b.sqlite"}
	view := &scanStatusView{ScanUUID: "c2b-row", EffectiveStatus: effStatusCompleted, Source: []string{"db"}}
	b := scanWaitDocument(reader, view)
	out, err := encodeAgentJSON(b.envelope())
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	assert.Equal(t, "scan wait", doc["command"])
	assert.Equal(t, "scan", doc["kind"])
	assert.Equal(t, "curtailed", doc["status"])
	assert.Equal(t, "partial", doc["completeness"])
	assert.Equal(t, "scan_budget", doc["stop_reason"])
	assert.Equal(t, "c2b-row", doc["scan_uuid"])
	assert.Equal(t, true, doc["persisted"])
	assert.Equal(t, agentTimestamp(started), doc["started_at"])
	assert.Equal(t, agentTimestamp(row.FinishedAt), doc["finished_at"])
	assert.EqualValues(t, row.DurationMs, doc["duration_ms"])
	targets, _ := doc["targets"].([]any)
	assert.Len(t, targets, 2)

	// The plan, verbatim: the same object the row stored.
	embedded, err := json.Marshal(doc["plan"])
	require.NoError(t, err)
	var got, want map[string]any
	require.NoError(t, json.Unmarshal(embedded, &got))
	require.NoError(t, json.Unmarshal(raw, &want))
	assert.Equal(t, want, got)

	// A failed row carries its error, and status failed.
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: "c2b-failed", ProjectUUID: database.DefaultProjectUUID, Status: "running", StartedAt: started}))
	require.NoError(t, repo.CompleteScan(ctx, "c2b-failed", "boom"))
	b = scanWaitDocument(reader, &scanStatusView{ScanUUID: "c2b-failed", EffectiveStatus: effStatusFailed, Source: []string{"db"}})
	out, err = encodeAgentJSON(b.envelope())
	require.NoError(t, err)
	doc = map[string]any{}
	require.NoError(t, json.Unmarshal(out, &doc))
	assert.Equal(t, "failed", doc["status"])
	assert.Nil(t, doc["plan"])
	errs, _ := doc["errors"].([]any)
	require.Len(t, errs, 1)
	assert.Equal(t, "boom", errs[0].(map[string]any)["message"])
}

// A scan known only from status.json (its row went with a -S scratch store):
// counts but no items, not persisted.
func TestScanWaitDocumentStatusFileOnly(t *testing.T) {
	withMachineDocumentState(t)
	globalJSON = true
	started := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	v := &scanStatusView{
		ScanUUID: "c2b-file", EffectiveStatus: effStatusCompleted, Completeness: database.CompletenessComplete,
		Findings: 3, FindingsBySeverity: map[string]int{"high": 1, "low": 2}, DurationMS: 60_000,
		Source: []string{"status_file"}, startedAt: started,
	}
	out, err := encodeAgentJSON(scanWaitDocument(&scanStatusReader{}, v).envelope())
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	assert.Equal(t, "completed", doc["status"])
	assert.Equal(t, false, doc["persisted"])
	assert.EqualValues(t, 3, doc["total"])
	assert.Equal(t, true, doc["items_truncated"])
	assert.EqualValues(t, 60_000, doc["duration_ms"])
	assert.Equal(t, agentTimestamp(started), doc["started_at"])
	counts := doc["counts_by_severity"].(map[string]any)
	assert.EqualValues(t, 1, counts["high"])
	assert.EqualValues(t, 2, counts["low"])
}

// status.json retention: files whose last write (heartbeat or mtime, the newer)
// is past the retention go, with their directory when it is left empty;
// anything newer, and everything else in a session directory, stays.
func TestPruneSessionStatusFiles(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	write := func(uuid string, beat, mtime time.Time) string {
		path := writeStatusFile(t, dir, runner.SessionStatus{ScanUUID: uuid, Status: runner.SessionCompleted, HeartbeatAt: beat})
		require.NoError(t, os.Chtimes(path, mtime, mtime))
		return path
	}
	old := now.Add(-40 * 24 * time.Hour)
	recent := now.Add(-2 * 24 * time.Hour)

	gone := write("old-only", old, old)
	withLog := write("old-with-log", old, old)
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(withLog), config.RuntimeLogFilename), []byte("x"), 0o600))
	kept := write("recent", recent, recent)
	// Old heartbeat but a recent mtime (rewritten without a beat): kept.
	touched := write("touched", old, recent)
	// Unparseable content ages out by mtime alone.
	garbage := filepath.Join(dir, "garbage", runner.SessionStatusFilename)
	require.NoError(t, os.MkdirAll(filepath.Dir(garbage), 0o755))
	require.NoError(t, os.WriteFile(garbage, []byte("{not json"), 0o600))
	require.NoError(t, os.Chtimes(garbage, old, old))
	// A session directory without a status file is not this pruner's.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "no-status"), 0o755))

	removed, err := pruneSessionStatusFiles(dir, 30*24*time.Hour, now)
	require.NoError(t, err)
	assert.Equal(t, 3, removed)
	assert.NoFileExists(t, gone)
	assert.NoDirExists(t, filepath.Dir(gone))
	assert.NoFileExists(t, withLog)
	assert.FileExists(t, filepath.Join(filepath.Dir(withLog), config.RuntimeLogFilename))
	assert.FileExists(t, kept)
	assert.FileExists(t, touched)
	assert.NoFileExists(t, garbage)
	assert.DirExists(t, filepath.Join(dir, "no-status"))

	// Retention 0 = keep forever; a missing directory is not an error.
	n, err := pruneSessionStatusFiles(dir, 0, now.Add(1000*24*time.Hour))
	assert.NoError(t, err)
	assert.Zero(t, n)
	n, err = pruneSessionStatusFiles(filepath.Join(dir, "absent"), time.Hour, now)
	assert.NoError(t, err)
	assert.Zero(t, n)
}

func TestStatusRetentionConfig(t *testing.T) {
	c := config.ScanLogsConfig{}
	assert.Equal(t, time.Duration(config.DefaultStatusRetentionDays)*24*time.Hour, c.StatusRetention())
	zero, seven := 0, 7
	c.StatusRetentionDays = &zero
	assert.Zero(t, c.StatusRetention())
	c.StatusRetentionDays = &seven
	assert.Equal(t, 7*24*time.Hour, c.StatusRetention())
}

// The reaper finalizes exactly the running rows whose liveness says abandoned:
// failed, partial, stop_reason abandoned, finished at the last write. A live
// row, a finished row, and a row in another project are left alone.
func TestReapAbandonedScans(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	stubLiveness(t, now, "here", func(int) bool { return true })
	repo := newC2bTestRepo(t)
	ctx := context.Background()
	sessions := t.TempDir()

	create := func(uuid, project string, started time.Time, beat *time.Time) {
		require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: uuid, ProjectUUID: project, Status: "running", StartedAt: started, CreatedAt: started, UpdatedAt: started}))
		if beat != nil {
			_, _, err := repo.UpdateScanHeartbeat(ctx, uuid, database.ScanHeartbeat{At: *beat, Phase: "discovery"})
			require.NoError(t, err)
		}
	}
	oldStart := now.Add(-3 * time.Hour)
	deadBeat := now.Add(-time.Hour)
	liveBeat := now.Add(-5 * time.Second)
	create("dead", database.DefaultProjectUUID, oldStart, &deadBeat)
	create("live", database.DefaultProjectUUID, oldStart, &liveBeat)
	create("other-project", "11111111-2222-3333-4444-555555555555", oldStart, &deadBeat)
	create("finished", database.DefaultProjectUUID, oldStart, nil)
	require.NoError(t, repo.CompleteScan(ctx, "finished", ""))

	reaped, err := reapAbandonedScans(ctx, repo, database.DefaultProjectUUID, sessions)
	require.NoError(t, err)
	assert.Equal(t, []string{"dead"}, reaped)

	dead, err := repo.GetScanByUUID(ctx, "dead")
	require.NoError(t, err)
	assert.Equal(t, "failed", dead.Status)
	assert.Equal(t, database.ReasonAbandoned, dead.StopReason)
	assert.Equal(t, database.CompletenessPartial, dead.Completeness)
	assert.Contains(t, dead.ErrorMessage, "abandoned")
	assert.WithinDuration(t, deadBeat, dead.FinishedAt, time.Second)
	assert.Equal(t, deadBeat.Sub(oldStart).Milliseconds(), dead.DurationMs)
	assert.Empty(t, dead.CurrentPhase)
	// The status views agree: no longer abandoned, failed.
	assert.Equal(t, effStatusFailed, effectiveStatus(dead.Status, dead.ErrorMessage, Liveness{Stale: true}))

	for uuid, want := range map[string]string{"live": "running", "other-project": "running", "finished": "completed"} {
		s, err := repo.GetScanByUUID(ctx, uuid)
		require.NoError(t, err)
		assert.Equal(t, want, s.Status, uuid)
	}

	// A second reap finds nothing; the write itself refuses a finalized row.
	reaped, err = reapAbandonedScans(ctx, repo, database.DefaultProjectUUID, sessions)
	require.NoError(t, err)
	assert.Empty(t, reaped)
	ok, err := repo.ReapAbandonedScan(ctx, dead, deadBeat)
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestAbandonedScanReaper: the server's periodic reaper finalizes
// abandoned rows in every project (not just the default), and leaves live ones.
func TestAbandonedScanReaper(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	stubLiveness(t, now, "here", func(int) bool { return true })
	repo := newC2bTestRepo(t)
	ctx := context.Background()
	other := "11111111-2222-3333-4444-555555555555"
	require.NoError(t, repo.CreateProject(ctx, &database.Project{UUID: other, Name: "other", OwnerUUID: database.DefaultUserUUID}))
	deadBeat := now.Add(-time.Hour)
	liveBeat := now.Add(-5 * time.Second)
	for uuid, spec := range map[string]struct {
		project string
		beat    time.Time
	}{
		"dead-default": {database.DefaultProjectUUID, deadBeat},
		"dead-other":   {other, deadBeat},
		"live-other":   {other, liveBeat},
	} {
		start := now.Add(-3 * time.Hour)
		require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: uuid, ProjectUUID: spec.project, Status: "running", StartedAt: start, CreatedAt: start, UpdatedAt: start}))
		_, _, err := repo.UpdateScanHeartbeat(ctx, uuid, database.ScanHeartbeat{At: spec.beat, Phase: "discovery"})
		require.NoError(t, err)
	}

	stop := startAbandonedScanReaper(repo, t.TempDir(), time.Hour)
	require.Eventually(t, func() bool {
		a, _ := repo.GetScanByUUID(ctx, "dead-default")
		b, _ := repo.GetScanByUUID(ctx, "dead-other")
		return a != nil && b != nil && a.Status == "failed" && b.Status == "failed"
	}, 5*time.Second, 20*time.Millisecond)
	stop()
	live, err := repo.GetScanByUUID(ctx, "live-other")
	require.NoError(t, err)
	assert.Equal(t, "running", live.Status)
}
