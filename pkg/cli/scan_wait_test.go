package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/database"
)

// fakeWaitClock advances only when the waiter sleeps.
type fakeWaitClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeWaitClock) Now() time.Time { return c.now }

func (c *fakeWaitClock) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}

func scriptedProbe(views ...*scanStatusView) (func(context.Context) (*scanStatusView, error), *int) {
	calls := 0
	return func(context.Context) (*scanStatusView, error) {
		i := calls
		if i >= len(views) {
			i = len(views) - 1
		}
		calls++
		return views[i], nil
	}, &calls
}

func waitErrCode(err error) apicontract.ErrorCode {
	var coded codedError
	if errors.As(err, &coded) {
		return coded.Code()
	}
	return ""
}

func TestScanWaitRunningThenCompleted(t *testing.T) {
	clock := &fakeWaitClock{now: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)}
	running := &scanStatusView{ScanUUID: "u", EffectiveStatus: effStatusRunning, Phase: "discovery"}
	done := &scanStatusView{ScanUUID: "u", EffectiveStatus: effStatusCompleted, Completeness: database.CompletenessComplete}
	probe, calls := scriptedProbe(running, running, done)
	var progress []string
	w := &scanWaiter{uuid: "u", probe: probe, clock: clock, timeout: time.Minute, poll: 2 * time.Second,
		onProgress: func(v *scanStatusView) { progress = append(progress, v.Phase) }}

	v, err := w.wait(context.Background())
	if err != nil || v != done {
		t.Fatalf("wait = %v, %v; want the completed view", v, err)
	}
	if *calls != 3 || len(progress) != 2 || len(clock.sleeps) != 2 || clock.sleeps[0] != 2*time.Second {
		t.Fatalf("calls %d, progress %v, sleeps %v", *calls, progress, clock.sleeps)
	}
	if err := scanWaitExit(v, nil, false); err != nil {
		t.Fatalf("completed scan exit = %v, want nil (exit 0)", err)
	}
}

func TestScanWaitAbandoned(t *testing.T) {
	clock := &fakeWaitClock{now: time.Unix(0, 0)}
	gone := true
	last := "2026-10-10T08:00:00.000Z"
	abandoned := &scanStatusView{ScanUUID: "u", EffectiveStatus: effStatusAbandoned, PID: 99,
		Liveness: scanLivenessView{Stale: true, LastWriteAt: &last, ProcessGone: &gone}}
	probe, _ := scriptedProbe(abandoned)
	w := &scanWaiter{uuid: "u", probe: probe, clock: clock, timeout: time.Hour, poll: time.Second}

	_, err := w.wait(context.Background())
	if waitErrCode(err) != apicontract.CodeScanAbandoned {
		t.Fatalf("err = %v (code %q), want scan_abandoned", err, waitErrCode(err))
	}
	if classifyExitCode(err) != ExitError {
		t.Errorf("exit = %d, want 1", classifyExitCode(err))
	}
	if !strings.Contains(err.Error(), "pid 99") {
		t.Errorf("message should name the dead pid: %v", err)
	}
}

func TestScanWaitTimeout(t *testing.T) {
	clock := &fakeWaitClock{now: time.Unix(0, 0)}
	running := &scanStatusView{ScanUUID: "u", EffectiveStatus: effStatusRunning, Phase: "dynamic-assessment"}
	probe, calls := scriptedProbe(running)
	w := &scanWaiter{uuid: "u", probe: probe, clock: clock, timeout: 5 * time.Second, poll: 2 * time.Second}

	v, err := w.wait(context.Background())
	if waitErrCode(err) != apicontract.CodeWaitTimeout {
		t.Fatalf("err = %v, want wait_timeout", err)
	}
	if v != running || !strings.Contains(err.Error(), "dynamic-assessment") {
		t.Errorf("timeout should report the last state: %v", err)
	}
	// 2s + 2s + the 1s remainder: the last sleep is clipped to the deadline.
	if got := clock.sleeps; len(got) != 3 || got[2] != time.Second {
		t.Errorf("sleeps = %v", got)
	}
	if *calls != 4 {
		t.Errorf("probes = %d, want 4", *calls)
	}
}

func TestScanWaitNotFoundGraceAndBusy(t *testing.T) {
	clock := &fakeWaitClock{now: time.Unix(0, 0)}
	notFound := codedErrorf(apicontract.CodeNotFound, "no scan")
	done := &scanStatusView{ScanUUID: "u", EffectiveStatus: effStatusCompleted}
	seq := []error{notFound, &database.LockedError{Op: "read scan", Err: errors.New("database is locked")}, nil}
	i := 0
	w := &scanWaiter{uuid: "u", clock: clock, timeout: time.Hour, poll: time.Second, notFoundGrace: 10 * time.Second,
		probe: func(context.Context) (*scanStatusView, error) {
			err := seq[i]
			i++
			if err != nil {
				return nil, err
			}
			return done, nil
		}}
	if v, err := w.wait(context.Background()); err != nil || v != done {
		t.Fatalf("wait = %v, %v; a not-yet-written row and a busy read must be retried", v, err)
	}

	// Past the grace, an unknown UUID fails.
	clock2 := &fakeWaitClock{now: time.Unix(0, 0)}
	w2 := &scanWaiter{uuid: "typo", clock: clock2, timeout: time.Hour, poll: 5 * time.Second, notFoundGrace: 10 * time.Second,
		probe: func(context.Context) (*scanStatusView, error) { return nil, notFound }}
	if _, err := w2.wait(context.Background()); waitErrCode(err) != apicontract.CodeNotFound {
		t.Fatalf("err = %v, want not_found after the grace", err)
	}
}

func TestScanWaitExitMapping(t *testing.T) {
	gateErr := gateError{err: errors.New("--fail-on high")}
	tripped := func() error { return gateErr }
	clean := func() error { return nil }
	partial := &scanStatusView{ScanUUID: "u", EffectiveStatus: effStatusCompleted, Completeness: database.CompletenessPartial, StopReason: "scan_budget"}

	for _, c := range []struct {
		name          string
		view          *scanStatusView
		gate          func() error
		failOnPartial bool
		wantExit      int
		wantCode      apicontract.ErrorCode
	}{
		{"complete", &scanStatusView{EffectiveStatus: effStatusCompleted}, clean, true, ExitSuccess, ""},
		{"failed", &scanStatusView{EffectiveStatus: effStatusFailed, ErrorMessage: "boom"}, tripped, true, ExitError, apicontract.CodeFailed},
		{"cancelled", &scanStatusView{EffectiveStatus: effStatusCancelled}, clean, false, ExitError, apicontract.CodeFailed},
		{"gate", &scanStatusView{EffectiveStatus: effStatusCompleted}, tripped, false, ExitFailOnGate, ""},
		{"gate beats partial", partial, tripped, true, ExitFailOnGate, ""},
		{"partial opted in", partial, clean, true, ExitIncomplete, apicontract.CodePartial},
		{"partial by default is success", partial, clean, false, ExitSuccess, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := scanWaitExit(c.view, c.gate, c.failOnPartial)
			if got := classifyExitCode(err); got != c.wantExit {
				t.Errorf("exit = %d, want %d (err %v)", got, c.wantExit, err)
			}
			if c.wantCode != "" {
				var inc incompleteError
				code := waitErrCode(err)
				if errors.As(err, &inc) {
					code = inc.Code()
				}
				if code != c.wantCode {
					t.Errorf("code = %q, want %q", code, c.wantCode)
				}
			}
		})
	}
}

func TestScanStatusViewETA(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	stubLiveness(t, now, "here", func(int) bool { return true })
	total := int64(1000)
	phaseStart := now.Add(-2 * time.Minute)
	file := &runner.SessionStatus{
		ScanUUID: "u", Status: runner.SessionRunning, Phase: "dynamic-assessment", PhaseStartedAt: &phaseStart,
		PhasesPlanned: []string{"discovery", "dynamic-assessment"}, PhasesDone: []string{"discovery"},
		Progress:  &runner.SessionProgress{Done: 250, Total: &total, Unit: "records"},
		StartedAt: now.Add(-10 * time.Minute), HeartbeatAt: now.Add(-3 * time.Second),
		ScanMaxDurationMS: (30 * time.Minute).Milliseconds(), RequestsSent: 900,
		FindingsBySeverity: map[string]int64{"high": 2}, Findings: 2,
	}
	lv := livenessFromSignals(livenessSignals{status: file})
	v := buildScanStatusView("u", nil, file, lv, now)

	if v.EffectiveStatus != effStatusRunning || v.Phase != "dynamic-assessment" || v.RequestsSent != 900 || v.FindingsBySeverity["high"] != 2 {
		t.Fatalf("view = %+v", v)
	}
	// 250 done in 2m → 750 left at the same rate = 6m; budget leaves 20m.
	if v.ETA.EstimateMS == nil || *v.ETA.EstimateMS != (6*time.Minute).Milliseconds() {
		t.Errorf("estimate = %v", v.ETA.EstimateMS)
	}
	if v.ETA.UpperBoundMS == nil || *v.ETA.UpperBoundMS != (20*time.Minute).Milliseconds() || v.ETA.Basis != "phase_rate+scan_budget" {
		t.Errorf("eta = %+v", v.ETA)
	}

	// A phase with phases still to come: no invented estimate.
	file.PhasesPlanned = []string{"dynamic-assessment", "known-issue-scan"}
	file.ScanMaxDurationMS = 0
	v = buildScanStatusView("u", nil, file, lv, now)
	if v.ETA.EstimateMS != nil || v.ETA.UpperBoundMS != nil || v.ETA.Basis != "unknown" {
		t.Errorf("eta without basis = %+v", v.ETA)
	}

	// Row present and finished: terminal ETA, row status wins over the file.
	row := &database.Scan{UUID: "u", Status: "completed", Completeness: "complete", DurationMs: 1234, StartedAt: now.Add(-time.Hour)}
	file.Status = runner.SessionCompleted
	v = buildScanStatusView("u", row, file, lv, now)
	if v.EffectiveStatus != effStatusCompleted || v.Phase != "" || v.Progress != nil || v.DurationMS != 1234 || v.ETA.Basis != "finished" {
		t.Errorf("terminal view = %+v", v)
	}
}

// ---- end to end: the real command against a seeded store -------------------

// runScanWaitChild runs `vigolium <args>` through the same re-exec child as the
// no-target tests, with HOME and --db pointing at a seeded throwaway store.
func runScanWaitChild(t *testing.T, home, db string, args ...string) (int, string, string) {
	t.Helper()
	full := append([]string{"--db", db}, args...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestScanNoTargetChild$", "-test.v=false")
	env := []string{a2ChildEnv + "=" + strings.Join(full, "\x1f"), "HOME=" + home, "NO_COLOR=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "VIGOLIUM_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	default:
		t.Fatalf("run child: %v", err)
		return -1, "", ""
	}
}

func seedScanStatusStore(t *testing.T) (home, dbPath string) {
	t.Helper()
	home = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".vigolium", initMarkerFileName), []byte("ok"), 0o600))
	dbPath = filepath.Join(home, "c2.sqlite")
	db, err := database.NewDB(&config.DatabaseConfig{
		Enabled: true, Driver: "sqlite",
		SQLite: config.SQLiteConfig{Path: dbPath, BusyTimeout: 5000, JournalMode: "WAL", Synchronous: "NORMAL"},
	})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, db.CreateSchema(ctx))
	require.NoError(t, db.SeedDefaults(ctx))
	repo := database.NewRepository(db)
	started := time.Now().Add(-time.Minute)
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: "c2-done", ProjectUUID: database.DefaultProjectUUID, Status: "running", StartedAt: started}))
	require.NoError(t, repo.UpdateScanPartial(ctx, &database.Scan{UUID: "c2-done", Plan: []byte(`{"schema_version":1,"scan_uuid":"c2-done","strategy":"balanced","heuristics_check":"basic","phases":[{"id":"discovery","enabled":true,"sends_target_traffic":true}],"budgets":{"scan_max_duration_ms":0,"max_requests":0,"max_requests_per_host":0,"rate_limit":0,"concurrency":0,"max_per_host":0},"modules":{"active":1,"passive":0,"extensions":0,"tier_ceiling":"","tier_filtered":0,"hygiene_suppressed":0,"risk_gated":0,"risky_payloads_allowed":false,"by_scope":{}},"scope":{},"auth":[],"targets":{"seeded":1,"from_files":0,"admitted":1,"rejected":0},"estimate":{"low":0,"high":0,"by_phase":{},"basis":"","confidence":""},"warnings":[]}`)}))
	require.NoError(t, repo.CompleteScanWithOutcome(ctx, "c2-done", "", database.ScanCompletion{Completeness: database.CompletenessPartial, StopReason: "scan_budget"}))
	// A "running" row whose heartbeat stopped long ago: an abandoned scan.
	old := time.Now().Add(-time.Hour)
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: "c2-dead", ProjectUUID: database.DefaultProjectUUID, Status: "running", StartedAt: old, CreatedAt: old, UpdatedAt: old}))
	_, _, err = repo.UpdateScanHeartbeat(ctx, "c2-dead", database.ScanHeartbeat{At: old, Phase: "discovery"})
	require.NoError(t, err)
	require.NoError(t, db.Close())
	return home, dbPath
}

func TestScanWaitCommandEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary")
	}
	home, db := seedScanStatusStore(t)

	code, stdout, stderr := runScanWaitChild(t, home, db, "scan", "wait", "c2-done", "-j")
	if code != 0 {
		t.Fatalf("exit = %d\nstdout:%s\nstderr:%s", code, stdout, stderr)
	}
	var env map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &env), stdout)
	contracttest.Validate(t, "scan wait", []byte(stdout))
	// The scan document, rebuilt from the row: kind scan, the row's verdict,
	// the stored plan verbatim.
	if env["command"] != "scan wait" || env["kind"] != "scan" || env["scan_uuid"] != "c2-done" {
		t.Errorf("envelope = %v", env)
	}
	if env["status"] != "curtailed" || env["completeness"] != "partial" || env["stop_reason"] != "scan_budget" {
		t.Errorf("verdict = %v / %v / %v", env["status"], env["completeness"], env["stop_reason"])
	}
	if plan, _ := env["plan"].(map[string]any); plan == nil || plan["strategy"] != "balanced" {
		t.Errorf("plan = %v", env["plan"])
	}
	if items, ok := env["items"].([]any); !ok || len(items) != 0 {
		t.Errorf("items = %v (no findings seeded)", env["items"])
	}

	code, stdout, _ = runScanWaitChild(t, home, db, "scan", "status", "c2-done", "-j")
	require.Equal(t, 0, code, stdout)
	contracttest.Validate(t, "scan status", []byte(stdout))
	if !strings.Contains(stdout, `"strategy":"balanced"`) {
		t.Errorf("scan status should embed the stored plan: %s", stdout)
	}

	code, _, stderr = runScanWaitChild(t, home, db, "scan", "wait", "c2-done", "--fail-on-partial")
	if code != ExitIncomplete {
		t.Errorf("--fail-on-partial exit = %d, want 5\n%s", code, stderr)
	}

	code, stdout, _ = runScanWaitChild(t, home, db, "scan", "wait", "c2-dead", "-j", "--timeout", "10s")
	if code != 1 || !strings.Contains(stdout, `"scan_abandoned"`) {
		t.Errorf("abandoned: exit %d stdout %s", code, stdout)
	}
	contracttest.ValidateError(t, []byte(stdout))

	code, stdout, _ = runScanWaitChild(t, home, db, "scan", "status", "c2-dead", "-j")
	if code != 0 || !strings.Contains(stdout, `"effective_status":"abandoned"`) {
		t.Errorf("status: exit %d stdout %s", code, stdout)
	}
	contracttest.Validate(t, "scan status", []byte(stdout))

	code, _, _ = runScanWaitChild(t, home, db, "scan", "wait", "c2-done", "--poll", "0s")
	if code != ExitUsageError {
		t.Errorf("--poll 0 exit = %d, want 2", code)
	}

	// log ls --reap finalizes the abandoned row; scan status then says failed.
	code, _, _ = runScanWaitChild(t, home, db, "--read-only", "log", "ls", "--reap")
	if code != ExitUsageError {
		t.Errorf("--read-only --reap exit = %d, want 2", code)
	}
	code, stdout, stderr = runScanWaitChild(t, home, db, "log", "ls", "--reap", "-j")
	require.Equal(t, 0, code, stderr)
	contracttest.Validate(t, "log ls", []byte(stdout))
	var reap struct {
		Reaped             []string `json:"reaped"`
		StatusFilesRemoved *int     `json:"status_files_removed"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &reap), stdout)
	if len(reap.Reaped) != 1 || reap.Reaped[0] != "c2-dead" || reap.StatusFilesRemoved == nil {
		t.Errorf("reap = %+v", reap)
	}
	code, stdout, _ = runScanWaitChild(t, home, db, "scan", "status", "c2-dead", "-j")
	if code != 0 || !strings.Contains(stdout, `"effective_status":"failed"`) || !strings.Contains(stdout, `"stop_reason":"abandoned"`) {
		t.Errorf("after reap: exit %d stdout %s", code, stdout)
	}
}

// The stderr progress line is repeated only when something other than the
// ETA changed, or after the quiet interval.
func TestScanWaitStderrProgressDedupe(t *testing.T) {
	clock := &fakeWaitClock{now: time.Unix(0, 0)}
	var buf bytes.Buffer
	progress := newWaitStderrProgress(&buf, clock)
	upper := func(ms int64) scanETAView { return scanETAView{UpperBoundMS: &ms, Basis: "scan_budget"} }
	v := &scanStatusView{ScanUUID: "abcdef0123", EffectiveStatus: effStatusRunning, Phase: "discovery", RequestsSent: 5}

	v.ETA = upper(60000)
	progress(v)
	clock.now = clock.now.Add(2 * time.Second)
	v.ETA = upper(58000) // only the ETA moved
	progress(v)
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Fatalf("lines = %d, want 1 (ETA-only change is not news):\n%s", n, buf.String())
	}
	v.RequestsSent = 9
	progress(v)
	clock.now = clock.now.Add(scanWaitQuietReprint)
	progress(v)
	if n := strings.Count(buf.String(), "\n"); n != 3 {
		t.Fatalf("lines = %d, want 3:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "eta at most") {
		t.Errorf("printed line should still carry the ETA:\n%s", buf.String())
	}
}
