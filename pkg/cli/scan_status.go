package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var scanStatusCmd = &cobra.Command{
	Use:   "status <scan-uuid>",
	Short: "Show a scan's live status: phase, progress, liveness and ETA",
	Long: `Show where a native scan is: its status, whether the process behind a
"running" row is still alive, the phase it is in, requests sent, findings by
severity, work-item progress and an ETA.

Liveness combines every signal the scan leaves: the runner's heartbeat
(status.json in the native session directory and the scan row's heartbeat
columns, refreshed every 10s), runtime.log, and the newest scan_logs line. A
running row that has written nothing for 2 minutes — or whose process is
confirmed gone on this host — reports effective_status "abandoned".

The ETA is never invented. upper_bound_ms is the tighter of the remaining
--scanning-max-duration budget and the remaining enabled phases' time ceilings
from the scan's stored plan. estimate_ms extrapolates the current phase's own
rate (when its total is known) and adds the phases still to come at 0.6 of
their ceilings. Either is null when there is no basis for it.

The item embeds the scan's stored plan verbatim as plan (null when the row has
none).

Reads the database like 'vigolium log' (-S/--db, --glob-db), and falls back to
status.json alone for a -S or --db-isolate scan whose row is not in that store.`,
	Example: FormatExamples(
		"# Where is this scan, and is it still alive?",
		"vigolium scan status 7c0e…-uuid",
		"# Machine-readable (one item)",
		"vigolium scan status 7c0e…-uuid -j",
	),
	Args: cobra.ExactArgs(1),
	RunE: runScanStatus,
}

func init() {
	scanCmd.AddCommand(scanStatusCmd)
	f := scanStatusCmd.Flags()
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a .jsonl export or standalone .sqlite) with project scoping off")
	f.StringVar(&globalGlobDB, "glob-db", "", "Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S")
}

// scanStatusView is one `scan status` item, and the document `scan wait`
// prints when the scan ends.
type scanStatusView struct {
	ScanUUID string `json:"scan_uuid"`
	// Status is the stored status (the row's, else status.json's).
	Status string `json:"status"`
	// EffectiveStatus is what to act on: running | abandoned | completed |
	// failed | cancelled.
	EffectiveStatus    string            `json:"effective_status"`
	Liveness           scanLivenessView  `json:"liveness"`
	Phase              string            `json:"phase,omitempty"`
	PhaseStartedAt     *string           `json:"phase_started_at,omitempty"`
	PhasesDone         []string          `json:"phases_done"`
	PhasesPlanned      []string          `json:"phases_planned,omitempty"`
	RequestsSent       int64             `json:"requests_sent"`
	Findings           int               `json:"findings"`
	FindingsBySeverity map[string]int    `json:"findings_by_severity"`
	Progress           *scanProgressView `json:"progress"`
	ETA                scanETAView       `json:"eta"`
	// Plan is the resolved plan the runner stored on the row (scans.plan, the
	// `schema plan` document), verbatim; null when the row has none.
	Plan         *scanplan.Plan `json:"plan"`
	Completeness string         `json:"completeness,omitempty"`
	StopReason   string         `json:"stop_reason,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	StartedAt    *string        `json:"started_at"`
	FinishedAt   *string        `json:"finished_at,omitempty"`
	DurationMS   int64          `json:"duration_ms"`
	PID          int            `json:"pid,omitempty"`
	RunnerHost   string         `json:"runner_host,omitempty"`
	ProjectUUID  string         `json:"project_uuid,omitempty"`
	DBPath       string         `json:"db_path,omitempty"`
	// Source says where the facts came from: "db", "status_file" or both.
	Source []string `json:"source"`

	// startedAt and phaseStarted are the parsed times the ETA is computed from;
	// finishedAt is the row's, for the scan document `scan wait` builds.
	startedAt    time.Time
	phaseStarted time.Time
	finishedAt   time.Time
	budgetMS     int64
}

type scanLivenessView struct {
	LastWriteAt *string  `json:"last_write_at"`
	Stale       bool     `json:"stale"`
	Sources     []string `json:"sources"`
	ProcessGone *bool    `json:"process_gone,omitempty"`
}

type scanProgressView struct {
	Done  int64  `json:"done"`
	Total *int64 `json:"total"`
	Unit  string `json:"unit"`
}

// scanETAView is the remaining-time estimate. Both figures are null when
// unknowable; basis names what they rest on.
type scanETAView struct {
	EstimateMS   *int64 `json:"estimate_ms"`
	UpperBoundMS *int64 `json:"upper_bound_ms"`
	// Basis: "finished", "unknown", or the "+"-joined inputs the figures rest
	// on, in this order: phase_rate (the current phase's own rate),
	// plan_ceilings (the stored plan's phase ceilings), scan_budget (the
	// remaining --scanning-max-duration).
	Basis string `json:"basis"`
}

// Effective statuses.
const (
	effStatusRunning   = "running"
	effStatusAbandoned = "abandoned"
	effStatusCompleted = "completed"
	effStatusFailed    = "failed"
	effStatusCancelled = "cancelled"
)

// isTerminalEffectiveStatus reports whether status ends a `scan wait`.
func isTerminalEffectiveStatus(status string) bool {
	switch status {
	case effStatusCompleted, effStatusFailed, effStatusCancelled:
		return true
	}
	return false
}

func runScanStatus(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	uuid := strings.TrimSpace(args[0])
	if uuid == "" {
		return usageErrorf("scan status needs a scan UUID")
	}
	reader, err := newScanStatusReader()
	if err != nil {
		return err
	}
	view, err := reader.read(context.Background(), uuid)
	if err != nil {
		return err
	}
	if globalJSON {
		return emitObject(cmd, "", view, withDBPath(view.DBPath), withQuery("log", uuid))
	}
	printScanStatusHuman(os.Stdout, view)
	return nil
}

// scanStatusReader resolves scan status views. It holds the store (nil when it
// could not be opened — status.json may still answer) and the sessions root.
type scanStatusReader struct {
	repo        *database.Repository
	dbErr       error
	sessionsDir string
	dbPath      string
}

// newScanStatusReader opens the read handle (read pool: polling must never take
// the write lock a running scan needs) and resolves the sessions directory.
func newScanStatusReader() (*scanStatusReader, error) {
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return nil, err
	}
	r := &scanStatusReader{sessionsDir: settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()}
	db, err := openReadDB(globDBSkipSet{Records: true})
	if err != nil {
		// A usage error (-S without --db) is the caller's to fix; anything else
		// leaves status.json to answer for a scan whose row is elsewhere.
		var usage usageError
		if errors.As(err, &usage) {
			return nil, err
		}
		r.dbErr = err
		return r, nil
	}
	r.repo = database.NewRepository(db)
	r.dbPath = resolvedReadDBPath()
	return r, nil
}

// read builds the view for uuid from the row and status.json. Not found in
// either is a not_found error.
func (r *scanStatusReader) read(ctx context.Context, uuid string) (*scanStatusView, error) {
	var row *database.Scan
	if r.repo != nil {
		err := database.RetryBusy(ctx, func() error {
			var getErr error
			row, getErr = r.repo.GetScanByUUID(ctx, uuid)
			return getErr
		}, database.RetryPolicy{Op: "read scan", MaxAttempts: 5, BaseDelay: 50 * time.Millisecond, MaxDelay: 500 * time.Millisecond})
		switch {
		case err == nil:
		case errors.Is(err, sql.ErrNoRows):
			row = nil
		case database.IsBusy(err):
			return nil, err
		default:
			// An unreadable row is an absent signal; status.json may still
			// answer, and if it does not, the error below names this one.
			row = nil
			if r.dbErr == nil {
				r.dbErr = err
			}
		}
	}
	statusPath := runner.SessionStatusPath(r.sessionsDir, uuid)
	file, fileErr := runner.ReadSessionStatus(statusPath)
	if fileErr != nil {
		file = nil
	}
	if row == nil && file == nil {
		if r.dbErr != nil {
			return nil, fmt.Errorf("no scan %s: database unavailable (%w) and no %s", uuid, r.dbErr, terminal.ShortenHome(statusPath))
		}
		return nil, codedErrorf(apicontract.CodeNotFound, "no scan found for uuid %s (checked the database and %s)", uuid, terminal.ShortenHome(statusPath))
	}

	lv := scanRowLiveness(ctx, r.repo, row, r.sessionsDir, uuid, resolveSessionLogPath(filepath.Join(r.sessionsDir, uuid)))

	view := buildScanStatusView(uuid, row, file, lv, livenessNow())
	if row != nil {
		view.DBPath = r.dbPath
		if r.repo != nil {
			if total, bySev, err := r.repo.ScanFindingTotal(ctx, uuid); err == nil {
				view.Findings, view.FindingsBySeverity = total, bySev
			}
		}
	}
	return view, nil
}

// buildScanStatusView merges the row (authoritative when present) and
// status.json (the only source of live progress, and of everything for a scan
// whose row lives in another store). Pure, for tests.
func buildScanStatusView(uuid string, row *database.Scan, file *runner.SessionStatus, lv Liveness, now time.Time) *scanStatusView {
	v := &scanStatusView{
		ScanUUID:           uuid,
		PhasesDone:         []string{},
		FindingsBySeverity: map[string]int{},
		Source:             []string{},
		Liveness: scanLivenessView{
			LastWriteAt: formatLivenessTime(lv.LastWriteAt),
			Sources:     lv.Sources,
			ProcessGone: lv.ProcessGone,
		},
	}
	if v.Liveness.Sources == nil {
		v.Liveness.Sources = []string{}
	}

	errorMessage := ""
	if row != nil {
		v.Source = append(v.Source, "db")
		v.Status = row.Status
		errorMessage = row.ErrorMessage
		v.ErrorMessage = row.ErrorMessage
		v.Phase = row.CurrentPhase
		v.RequestsSent = row.TotalRequests
		v.Completeness = row.Completeness
		v.StopReason = row.StopReason
		v.startedAt = row.StartedAt
		v.PID, v.RunnerHost = row.PID, row.RunnerHost
		v.ProjectUUID = row.ProjectUUID
		v.Findings = int(row.TotalFindings)
		for _, p := range row.PhaseOutcomes {
			if p.Phase != "" && p.Phase != string(runner.PhasePreflight) {
				v.PhasesDone = append(v.PhasesDone, p.Phase)
			}
		}
		if !row.FinishedAt.IsZero() {
			v.finishedAt = row.FinishedAt
			v.FinishedAt = formatLivenessTime(row.FinishedAt)
		}
		v.Plan = storedScanPlan(row)
	}
	if file != nil {
		v.Source = append(v.Source, "status_file")
		if row == nil {
			v.Status = file.Status
			v.startedAt = file.StartedAt
			v.PID, v.RunnerHost = file.PID, file.Host
			v.ProjectUUID = file.ProjectUUID
			v.DBPath = file.DBPath
			v.Findings = int(file.Findings)
			for sev, n := range file.FindingsBySeverity {
				v.FindingsBySeverity[sev] = int(n)
			}
		}
		if file.RequestsSent > v.RequestsSent {
			v.RequestsSent = file.RequestsSent
		}
		v.PhasesPlanned = file.PhasesPlanned
		v.budgetMS = file.ScanMaxDurationMS
		// Live facts only while the file itself says running: a finished
		// scan's last phase is history, not "the phase it is in".
		if file.Status == runner.SessionRunning {
			if file.Phase != "" {
				v.Phase = file.Phase
			}
			if file.PhaseStartedAt != nil {
				v.phaseStarted = *file.PhaseStartedAt
				v.PhaseStartedAt = formatLivenessTime(*file.PhaseStartedAt)
			}
			if file.Progress != nil && v.Phase == file.Phase {
				v.Progress = &scanProgressView{Done: file.Progress.Done, Total: file.Progress.Total, Unit: file.Progress.Unit}
			}
		}
		if len(v.PhasesDone) == 0 && len(file.PhasesDone) > 0 {
			v.PhasesDone = append(v.PhasesDone, file.PhasesDone...)
		}
	}
	if p := v.Plan; p != nil {
		if v.budgetMS == 0 {
			v.budgetMS = p.Budgets.ScanMaxDurationMS
		}
		if len(v.PhasesPlanned) == 0 {
			v.PhasesPlanned = planPhaseOrder(p)
		}
	}

	v.EffectiveStatus = effectiveStatus(v.Status, errorMessage, lv)
	v.Liveness.Stale = v.Status == "running" && lv.Stale
	if v.EffectiveStatus != effStatusRunning {
		// Not running (anymore): no current phase or progress to report.
		v.Phase, v.PhaseStartedAt, v.Progress = "", nil, nil
	}

	if !v.startedAt.IsZero() {
		v.StartedAt = formatLivenessTime(v.startedAt)
	}
	switch {
	case row != nil && row.DurationMs > 0 && v.Status != "running":
		v.DurationMS = row.DurationMs
	case !v.startedAt.IsZero():
		end := now
		if v.EffectiveStatus == effStatusAbandoned && !lv.LastWriteAt.IsZero() {
			end = lv.LastWriteAt
		}
		if d := end.Sub(v.startedAt).Milliseconds(); d > 0 {
			v.DurationMS = d
		}
	}
	v.ETA = scanETA(v, now)
	return v
}

// etaRemainingPhasesFactor discounts the remaining phases' ceilings when they
// are folded into an estimate: phases routinely finish well inside them.
const etaRemainingPhasesFactor = 0.6

// ETA basis names, joined with "+" in this order.
const (
	etaBasisPhaseRate     = "phase_rate"
	etaBasisPlanCeilings  = "plan_ceilings"
	etaBasisScanBudget    = "scan_budget"
	etaBasisFinished      = "finished"
	etaBasisUnknown       = "unknown"
	etaRemainingUnbounded = -1
)

// scanETA computes the remaining-time estimate from what the view can prove.
//
//   - upper_bound_ms: the tighter of the remaining --scanning-max-duration
//     budget and the stored plan's ceilings for what is left (the current
//     phase's ceiling minus its elapsed time, plus every later enabled phase's
//     ceiling). A phase without a ceiling makes the plan figure unknowable.
//   - estimate_ms: the current phase's own rate, elapsed × (total−done)/done,
//     when its total is known, plus the later phases' ceilings ×
//     etaRemainingPhasesFactor. With later phases and no plan (or a later
//     phase without a ceiling) there is no honest figure for them, so the
//     estimate stays null rather than reporting the current phase's tail as
//     the scan's.
//
// The estimate is clamped by the upper bound. Terminal scans report 0/0.
func scanETA(v *scanStatusView, now time.Time) scanETAView {
	if isTerminalEffectiveStatus(v.EffectiveStatus) {
		zero := int64(0)
		return scanETAView{EstimateMS: &zero, UpperBoundMS: &zero, Basis: etaBasisFinished}
	}
	eta := scanETAView{Basis: etaBasisUnknown}
	if v.EffectiveStatus != effStatusRunning {
		return eta
	}
	used := map[string]bool{}

	// The current phase's tail at its own rate; 0 between phases.
	var current *int64
	if v.Phase == "" {
		zero := int64(0)
		current = &zero
	} else if p := v.Progress; p != nil && p.Total != nil && p.Done > 0 && !v.phaseStarted.IsZero() {
		elapsed := now.Sub(v.phaseStarted).Milliseconds()
		if remaining := *p.Total - p.Done; elapsed > 0 && remaining >= 0 {
			est := int64(float64(elapsed) * float64(remaining) / float64(p.Done))
			current = &est
		}
	}

	later, laterKnown := laterPhases(v)
	if current != nil {
		switch {
		case laterKnown && len(later) == 0:
			// The last phase: its own tail is the whole estimate. (Between
			// phases with none left the scan is finalizing; nothing to rate.)
			if v.Phase != "" {
				eta.EstimateMS = current
				used[etaBasisPhaseRate] = true
			}
		case laterKnown && v.Plan != nil:
			if sum := planCeilingSum(v.Plan, later); sum >= 0 {
				est := *current + int64(float64(sum)*etaRemainingPhasesFactor)
				eta.EstimateMS = &est
				used[etaBasisPhaseRate] = v.Phase != ""
				used[etaBasisPlanCeilings] = true
			}
		}
	}

	var bounds []int64
	if v.Plan != nil && laterKnown {
		if left := planRemainingCeiling(v, later, now); left >= 0 {
			bounds = append(bounds, left)
			used[etaBasisPlanCeilings] = true
		}
	}
	if v.budgetMS > 0 && !v.startedAt.IsZero() {
		bounds = append(bounds, max(v.budgetMS-now.Sub(v.startedAt).Milliseconds(), 0))
		used[etaBasisScanBudget] = true
	}
	if len(bounds) > 0 {
		upper := slices.Min(bounds)
		eta.UpperBoundMS = &upper
	}
	if eta.EstimateMS != nil && eta.UpperBoundMS != nil && *eta.EstimateMS > *eta.UpperBoundMS {
		clamped := *eta.UpperBoundMS
		eta.EstimateMS = &clamped
	}

	var bases []string
	for _, b := range []string{etaBasisPhaseRate, etaBasisPlanCeilings, etaBasisScanBudget} {
		if used[b] {
			bases = append(bases, b)
		}
	}
	if len(bases) > 0 && (eta.EstimateMS != nil || eta.UpperBoundMS != nil) {
		eta.Basis = strings.Join(bases, "+")
	}
	return eta
}

// laterPhases returns the enabled phases that come after the current one (or,
// between phases, after the last one done), in plan order. ok is false when
// the order is unknown (no plan and no planned list) or the current phase is
// not in it.
func laterPhases(v *scanStatusView) (later []string, ok bool) {
	order := v.PhasesPlanned
	if v.Plan != nil {
		order = planPhaseOrder(v.Plan)
	}
	if len(order) == 0 {
		return nil, false
	}
	idx := -1
	if v.Phase != "" {
		idx = slices.Index(order, v.Phase)
		if idx < 0 {
			return nil, false
		}
	} else {
		for _, done := range v.PhasesDone {
			idx = max(idx, slices.Index(order, done))
		}
	}
	return order[idx+1:], true
}

// planPhaseOrder is the plan's enabled phases in execution order, without the
// preflight (a handful of GETs, which never carries a budget).
func planPhaseOrder(p *scanplan.Plan) []string {
	ids := p.EnabledPhaseIDs()
	return slices.DeleteFunc(ids, func(id string) bool { return id == string(runner.PhasePreflight) })
}

// planPhaseCeilingMS is the longest the plan lets phase id run, or
// etaRemainingUnbounded when nothing bounds it: no budget, a per-call budget,
// or a per-target budget with no admitted-target count to multiply.
func planPhaseCeilingMS(p *scanplan.Plan, id string) int64 {
	ph := p.Phase(id)
	if ph == nil || ph.Budget == nil {
		return etaRemainingUnbounded
	}
	b := ph.Budget
	switch {
	case b.PhaseCeilingMS > 0:
		return b.PhaseCeilingMS
	case b.Semantics == scanplan.SemanticsPerTarget && b.PerTargetMS > 0 && p.Targets.Admitted > 0:
		return (b.PerTargetMS + b.GraceMS) * int64(p.Targets.Admitted)
	}
	return etaRemainingUnbounded
}

// planCeilingSum adds the ceilings of ids, etaRemainingUnbounded when any is
// unbounded.
func planCeilingSum(p *scanplan.Plan, ids []string) int64 {
	var sum int64
	for _, id := range ids {
		c := planPhaseCeilingMS(p, id)
		if c < 0 {
			return etaRemainingUnbounded
		}
		sum += c
	}
	return sum
}

// planRemainingCeiling bounds what is left by the plan: the current phase's
// ceiling less the time it has already run, plus the later phases' ceilings.
func planRemainingCeiling(v *scanStatusView, later []string, now time.Time) int64 {
	sum := planCeilingSum(v.Plan, later)
	if sum < 0 || v.Phase == "" {
		return sum
	}
	c := planPhaseCeilingMS(v.Plan, v.Phase)
	if c < 0 {
		return etaRemainingUnbounded
	}
	if !v.phaseStarted.IsZero() {
		c = max(c-now.Sub(v.phaseStarted).Milliseconds(), 0)
	}
	return c + sum
}

// printScanStatusHuman renders the view as an aligned key/value block.
func printScanStatusHuman(w *os.File, v *scanStatusView) {
	row := func(k, val string) {
		_, _ = fmt.Fprintf(w, "  %s %s\n", terminal.Gray(fmt.Sprintf("%-14s", k)), val)
	}
	status := colorRunStatus(v.EffectiveStatus)
	if v.EffectiveStatus != v.Status && v.Status != "" {
		status += terminal.Gray(" (stored: " + v.Status + ")")
	}
	_, _ = fmt.Fprintf(w, "%s %s\n", terminal.InfoSymbol(), terminal.BoldCyan(v.ScanUUID))
	row("status", status)
	if v.Phase != "" {
		row("phase", v.Phase)
	}
	if len(v.PhasesDone) > 0 {
		row("phases done", strings.Join(v.PhasesDone, ", "))
	}
	if p := v.Progress; p != nil {
		total := "?"
		if p.Total != nil {
			total = fmt.Sprintf("%d", *p.Total)
		}
		row("progress", fmt.Sprintf("%d/%s %s", p.Done, total, p.Unit))
	}
	row("requests", fmt.Sprintf("%d", v.RequestsSent))
	row("findings", formatStatusSeverityCounts(v.Findings, v.FindingsBySeverity))
	if v.Completeness != "" {
		c := v.Completeness
		if v.StopReason != "" {
			c += " (" + v.StopReason + ")"
		}
		row("completeness", c)
	}
	row("duration", fmtStatusDuration(v.DurationMS))
	row("eta", formatETA(v.ETA))
	last := "never"
	if v.Liveness.LastWriteAt != nil {
		last = *v.Liveness.LastWriteAt
	}
	row("last write", fmt.Sprintf("%s %s", last, terminal.Gray("("+strings.Join(v.Liveness.Sources, ", ")+")")))
	if v.ErrorMessage != "" && v.EffectiveStatus == effStatusFailed {
		row("error", v.ErrorMessage)
	}
}

func formatStatusSeverityCounts(total int, bySev map[string]int) string {
	if total == 0 {
		return "0"
	}
	var parts []string
	for i := len(severityOrder) - 1; i >= 0; i-- {
		if n := bySev[severityOrder[i]]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", severityOrder[i], n))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d", total)
	}
	return fmt.Sprintf("%d (%s)", total, strings.Join(parts, ", "))
}

func fmtStatusDuration(ms int64) string {
	return (time.Duration(ms) * time.Millisecond).Round(time.Second).String()
}

func formatETA(e scanETAView) string {
	switch {
	case e.Basis == "finished":
		return "done"
	case e.EstimateMS != nil && e.UpperBoundMS != nil:
		return fmt.Sprintf("~%s (at most %s)", fmtStatusDuration(*e.EstimateMS), fmtStatusDuration(*e.UpperBoundMS))
	case e.EstimateMS != nil:
		return "~" + fmtStatusDuration(*e.EstimateMS)
	case e.UpperBoundMS != nil:
		return "at most " + fmtStatusDuration(*e.UpperBoundMS)
	}
	return "unknown"
}
