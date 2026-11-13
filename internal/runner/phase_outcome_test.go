package runner

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
)

// newLedger returns a tracker with no event stream attached — the configuration
// of every scan that does not pass --events, and the one in which the outcome
// ledger used to record nothing at all.
func newLedger(phase string) *phaseTracker {
	return &phaseTracker{phase: phase, start: time.Now()}
}

// TestTrackerRecordsWithEventsOff is the regression this work exists for. The
// ledger feeds the scan row and the terminal banner, so it has to be populated
// on a plain CLI run; previously the only writer ran inside an `if
// scanevents.On()` guard and a curtailed scan left no structured trace.
func TestTrackerRecordsWithEventsOff(t *testing.T) {
	tr := newLedger("discovery")
	tr.markPartial(database.ReasonTargetsFailed)
	tr.noteLimit(database.LimitTargetBudget)
	tr.noteError(errString("host unreachable"))

	out := tr.finish(context.Background(), nil)
	if out.Phase != "discovery" {
		t.Errorf("Phase = %q", out.Phase)
	}
	if out.State != database.PhaseFailed {
		t.Errorf("State = %q, want failed (an error was noted)", out.State)
	}
	if out.Errors != 1 {
		t.Errorf("Errors = %d, want 1", out.Errors)
	}
	if out.Message != "host unreachable" {
		t.Errorf("Message = %q", out.Message)
	}
	if !reflect.DeepEqual(out.Reasons, []string{database.ReasonTargetsFailed}) {
		t.Errorf("Reasons = %v", out.Reasons)
	}
	if !reflect.DeepEqual(out.Limits, []string{database.LimitTargetBudget}) {
		t.Errorf("Limits = %v", out.Limits)
	}
}

func TestTrackerPartialThenError(t *testing.T) {
	tr := newLedger("dynamic-assessment")
	tr.markPartial(database.ReasonPhaseDeadline)
	tr.noteError(errString("round 2 blew up"))

	out := tr.finish(context.Background(), nil)
	if out.State != database.PhaseFailed {
		t.Errorf("State = %q, want failed", out.State)
	}
	// The reason survives alongside the failure: an operator needs to know the
	// phase was ALSO cut short, not just that something errored.
	if !reflect.DeepEqual(out.Reasons, []string{database.ReasonPhaseDeadline}) {
		t.Errorf("Reasons = %v", out.Reasons)
	}
}

// TestTrackerLimitOnlyStaysCompleted pins that a configured bound does not
// degrade a phase. A per-target time box firing is the scan working as asked.
func TestTrackerLimitOnlyStaysCompleted(t *testing.T) {
	tr := newLedger("spidering")
	tr.noteLimit(database.LimitTargetBudget)

	out := tr.finish(context.Background(), nil)
	if out.State != database.PhaseCompleted {
		t.Errorf("State = %q, want completed", out.State)
	}
	if len(out.Limits) != 1 {
		t.Errorf("Limits = %v, want the limit to be reported", out.Limits)
	}
	if len(out.Reasons) != 0 {
		t.Errorf("a limit must not become a reason: %v", out.Reasons)
	}
}

func TestTrackerSkippedNoModules(t *testing.T) {
	tr := newLedger("dynamic-assessment")
	tr.markSkipped(database.ReasonNoModules)

	out := tr.finish(context.Background(), nil)
	if out.State != database.PhaseSkipped {
		t.Errorf("State = %q, want skipped", out.State)
	}
	if !reflect.DeepEqual(out.Reasons, []string{database.ReasonNoModules}) {
		t.Errorf("Reasons = %v", out.Reasons)
	}
}

func TestTrackerReasonsAreSortedAndDeduplicated(t *testing.T) {
	tr := newLedger("discovery")
	tr.markPartial(database.ReasonTargetsSkipped)
	tr.markPartial(database.ReasonCancelled)
	tr.markPartial(database.ReasonTargetsSkipped)

	out := tr.finish(context.Background(), nil)
	want := []string{database.ReasonCancelled, database.ReasonTargetsSkipped}
	if !reflect.DeepEqual(out.Reasons, want) {
		t.Errorf("Reasons = %v, want %v", out.Reasons, want)
	}
}

func TestTrackerFinishReadsTheContext(t *testing.T) {
	t.Run("deadline is the scan budget", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		<-ctx.Done()

		out := newLedger("probe").finish(ctx, nil)
		if !hasReason(out, database.ReasonScanBudget) {
			t.Errorf("Reasons = %v, want scan_budget", out.Reasons)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		out := newLedger("probe").finish(ctx, nil)
		if !hasReason(out, database.ReasonCancelled) {
			t.Errorf("Reasons = %v, want cancelled", out.Reasons)
		}
	})
	t.Run("live context adds nothing", func(t *testing.T) {
		out := newLedger("probe").finish(context.Background(), nil)
		if len(out.Reasons) != 0 {
			t.Errorf("Reasons = %v, want none", out.Reasons)
		}
		if out.State != database.PhaseCompleted {
			t.Errorf("State = %q", out.State)
		}
	})
}

// TestTrackerFinishRecordsReturnedErrorOnce guards against the error being
// double-counted: the arms that log-and-continue call noteError themselves, and
// finish also records whatever the caller returns. A phase must not report two
// errors for one failure.
func TestTrackerFinishRecordsReturnedErrorOnce(t *testing.T) {
	tr := newLedger("seed")
	out := tr.finish(context.Background(), errString("seeding failed"))
	if out.Errors != 1 {
		t.Errorf("Errors = %d, want 1", out.Errors)
	}
	if out.Message != "seeding failed" {
		t.Errorf("Message = %q", out.Message)
	}
}

func TestTrackerMessageIsBounded(t *testing.T) {
	huge := strings.Repeat("x", database.OutcomeMessageMax*3)
	out := newLedger("probe").finish(context.Background(), errString(huge))
	if len(out.Message) > database.OutcomeMessageMax {
		t.Errorf("Message length = %d, want <= %d", len(out.Message), database.OutcomeMessageMax)
	}
}

func TestTrackerAddPersistence(t *testing.T) {
	t.Run("clean outcome does not degrade the phase", func(t *testing.T) {
		tr := newLedger("discovery")
		tr.addPersistence(database.PersistenceOutcome{
			Writer: database.PersistenceWriterRecords, Accepted: 10, Committed: 10,
		})
		out := tr.finish(context.Background(), nil)
		if out.State != database.PhaseCompleted {
			t.Errorf("State = %q, want completed", out.State)
		}
		if out.Persistence == nil || out.Persistence.Committed != 10 {
			t.Errorf("Persistence = %+v", out.Persistence)
		}
	})
	t.Run("lost writes make the phase partial", func(t *testing.T) {
		tr := newLedger("discovery")
		tr.addPersistence(database.PersistenceOutcome{
			Writer: database.PersistenceWriterRecords, Accepted: 10, Committed: 7, Failed: 3,
		})
		out := tr.finish(context.Background(), nil)
		if out.State != database.PhasePartial {
			t.Errorf("State = %q, want partial", out.State)
		}
		if !hasReason(out, database.ReasonPersistence) {
			t.Errorf("Reasons = %v, want persistence_incomplete", out.Reasons)
		}
	})
	t.Run("two writers merge into one figure", func(t *testing.T) {
		tr := newLedger("dynamic-assessment")
		tr.addPersistence(database.PersistenceOutcome{
			Writer: database.PersistenceWriterFindings, Accepted: 4, Committed: 4,
		})
		tr.addPersistence(database.PersistenceOutcome{
			Writer: database.PersistenceWriterRecords, Accepted: 6, Committed: 6,
		})
		out := tr.finish(context.Background(), nil)
		if out.Persistence == nil {
			t.Fatal("Persistence missing")
		}
		if out.Persistence.Accepted != 10 || out.Persistence.Writer != database.PersistenceWriterMixed {
			t.Errorf("Persistence = %+v, want 10 accepted on a mixed writer", out.Persistence)
		}
	})
}

func TestTrackerNoteExecution(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rep       core.ExecutionReport
		wantState database.PhaseState
		want      []string
	}{
		{"clean", core.ExecutionReport{}, database.PhaseCompleted, nil},
		{"stopped early", core.ExecutionReport{StoppedEarly: true}, database.PhasePartial,
			[]string{database.ReasonInputIncomplete}},
		{"drain stalled", core.ExecutionReport{DrainStalled: true}, database.PhasePartial,
			[]string{database.ReasonDrainStalled}},
		{"abandoned workers skip the flush", core.ExecutionReport{
			WorkersAbandoned: true, DeferredFlushSkipped: true,
		}, database.PhasePartial, []string{
			database.ReasonDeferredFlushSkipped, database.ReasonWorkersAbandoned,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newLedger("dynamic-assessment")
			tr.noteExecution(tc.rep)
			out := tr.finish(context.Background(), nil)
			if out.State != tc.wantState {
				t.Errorf("State = %q, want %q", out.State, tc.wantState)
			}
			if !reflect.DeepEqual(out.Reasons, tc.want) {
				t.Errorf("Reasons = %v, want %v", out.Reasons, tc.want)
			}
		})
	}
}

// TestTrackerNoteExecutionSumsUnacked covers dynamic assessment, which runs one
// executor per feedback round against a single tracker.
func TestTrackerNoteExecutionSumsUnacked(t *testing.T) {
	tr := newLedger("dynamic-assessment")
	tr.noteExecution(core.ExecutionReport{StoppedEarly: true, Unacked: 3})
	tr.noteExecution(core.ExecutionReport{StoppedEarly: true, Unacked: 4})

	out := tr.finish(context.Background(), nil)
	if out.Unprocessed != 7 {
		t.Errorf("Unprocessed = %d, want 7", out.Unprocessed)
	}
}

func TestTrackerNilIsSafe(t *testing.T) {
	var tr *phaseTracker
	tr.markPartial(database.ReasonCancelled)
	tr.noteLimit(database.LimitTargetBudget)
	tr.markSkipped(database.ReasonNoModules)
	tr.addPersistence(database.PersistenceOutcome{Failed: 1})
	tr.noteExecution(core.ExecutionReport{WorkersAbandoned: true})
	tr.noteError(errString("x"))
	tr.recordFinding()
	if out := tr.finish(context.Background(), errString("y")); out.Phase != "" {
		t.Errorf("nil tracker produced an outcome: %+v", out)
	}
}

// TestTrackedPhaseDeadlineMarksOwnDeadline is the fix for the invisible per-phase
// budget: a phase that ran out of its own max_duration inside a healthy scan used
// to report a clean completion, because only the OUTER context was consulted.
func TestTrackedPhaseDeadlineMarksOwnDeadline(t *testing.T) {
	r := &Runner{}
	tr := newLedger("probe")
	r.currentPhase.Store(tr)

	ctx, cancel := r.trackedPhaseDeadline(context.Background(), 20*time.Millisecond)
	<-ctx.Done()
	cancel()

	out := tr.finish(context.Background(), nil)
	if !hasReason(out, database.ReasonPhaseDeadline) {
		t.Errorf("Reasons = %v, want phase_deadline", out.Reasons)
	}
	if out.State != database.PhasePartial {
		t.Errorf("State = %q, want partial", out.State)
	}
}

// TestTrackedPhaseDeadlineIgnoresParentCancel pins the other half: when the
// SCAN was cancelled, the phase did not run out of its own budget, and marking
// every still-running phase with phase_deadline would turn one scan-level fact
// into a per-phase defect repeated N times.
func TestTrackedPhaseDeadlineIgnoresParentCancel(t *testing.T) {
	r := &Runner{}
	tr := newLedger("probe")
	r.currentPhase.Store(tr)

	parent, parentCancel := context.WithCancel(context.Background())
	ctx, cancel := r.trackedPhaseDeadline(parent, time.Hour)
	parentCancel()
	<-ctx.Done()
	cancel()

	out := tr.finish(context.Background(), nil)
	if hasReason(out, database.ReasonPhaseDeadline) {
		t.Errorf("a cancelled parent must not read as the phase's own deadline: %v", out.Reasons)
	}
}

// TestTrackedPhaseDeadlineUnbounded keeps the no-budget path a pass-through, so
// an unconfigured phase neither gets a deadline nor a spurious mark.
func TestTrackedPhaseDeadlineUnbounded(t *testing.T) {
	r := &Runner{}
	tr := newLedger("probe")
	r.currentPhase.Store(tr)

	ctx, cancel := r.trackedPhaseDeadline(context.Background(), 0)
	if _, ok := ctx.Deadline(); ok {
		t.Error("a non-positive budget must not install a deadline")
	}
	cancel()
	if out := tr.finish(context.Background(), nil); len(out.Reasons) != 0 {
		t.Errorf("Reasons = %v, want none", out.Reasons)
	}
}

func TestTargetBudgetExhausted(t *testing.T) {
	t.Run("own deadline", func(t *testing.T) {
		parent := context.Background()
		target, cancel := context.WithTimeout(parent, time.Millisecond)
		defer cancel()
		<-target.Done()
		if !targetBudgetExhausted(target, parent) {
			t.Error("a target whose own deadline fired must report exhausted")
		}
	})
	t.Run("parent expired first", func(t *testing.T) {
		parent, parentCancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer parentCancel()
		<-parent.Done()
		target, cancel := context.WithTimeout(parent, time.Hour)
		defer cancel()
		// The child inherits DeadlineExceeded from the parent, which is exactly
		// why the parent has to be consulted.
		if targetBudgetExhausted(target, parent) {
			t.Error("the phase ceiling firing is not the target spending its budget")
		}
	})
	t.Run("still live", func(t *testing.T) {
		parent := context.Background()
		target, cancel := context.WithTimeout(parent, time.Hour)
		defer cancel()
		if targetBudgetExhausted(target, parent) {
			t.Error("a live target must not report exhausted")
		}
	})
	t.Run("parent cancelled", func(t *testing.T) {
		parent, parentCancel := context.WithCancel(context.Background())
		target, cancel := context.WithTimeout(parent, time.Hour)
		defer cancel()
		parentCancel()
		<-target.Done()
		if targetBudgetExhausted(target, parent) {
			t.Error("a cancelled parent is not the target spending its budget")
		}
	})
}

func TestScanStopReason(t *testing.T) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expCancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer expCancel()
	<-expired.Done()

	for _, tc := range []struct {
		name        string
		budget, run context.Context
		want        string
	}{
		{"all live", context.Background(), context.Background(), ""},
		// Cancellation outranks the budget: an operator who pressed Ctrl-C needs
		// to see that, not the deadline the cancel happened to trip.
		{"cancelled run", expired, done, database.ReasonCancelled},
		{"budget fired", expired, context.Background(), database.ReasonScanBudget},
		{"budget cancelled", done, context.Background(), database.ReasonCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanStopReason(tc.budget, tc.run); got != tc.want {
				t.Errorf("scanStopReason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCompletion(t *testing.T) {
	for _, tc := range []struct {
		name           string
		phases         []database.PhaseOutcome
		stopReason     string
		wantComplete   string
		wantStopReason string
	}{
		{
			name: "every phase clean",
			phases: []database.PhaseOutcome{
				{Phase: "discovery", State: database.PhaseCompleted},
				{Phase: "dynamic-assessment", State: database.PhaseCompleted},
			},
			wantComplete: database.CompletenessComplete,
		},
		{
			// A limit reached is designed behaviour, so it must not cost the scan
			// its clean verdict.
			name: "limits only",
			phases: []database.PhaseOutcome{
				{Phase: "spidering", State: database.PhaseCompleted, Limits: []string{database.LimitTargetBudget}},
			},
			wantComplete: database.CompletenessComplete,
		},
		{
			name: "no modules is a complete scan",
			phases: []database.PhaseOutcome{
				{Phase: "discovery", State: database.PhaseCompleted},
				{Phase: "dynamic-assessment", State: database.PhaseSkipped, Reasons: []string{database.ReasonNoModules}},
			},
			wantComplete: database.CompletenessComplete,
		},
		{
			name: "a partial phase makes the scan partial",
			phases: []database.PhaseOutcome{
				{Phase: "discovery", State: database.PhasePartial, Reasons: []string{database.ReasonTargetsFailed}},
				{Phase: "dynamic-assessment", State: database.PhaseCompleted},
			},
			wantComplete:   database.CompletenessPartial,
			wantStopReason: database.ReasonTargetsFailed,
		},
		{
			name: "a failed phase makes the scan partial",
			phases: []database.PhaseOutcome{
				{Phase: "probe", State: database.PhaseFailed, Errors: 1},
			},
			wantComplete:   database.CompletenessPartial,
			wantStopReason: database.ReasonError,
		},
		{
			name: "budget-skipped phases make the scan partial",
			phases: []database.PhaseOutcome{
				{Phase: "discovery", State: database.PhaseCompleted},
				{Phase: "known-issue-scan", State: database.PhaseSkipped, Reasons: []string{database.ReasonScanBudget}},
			},
			stopReason:     database.ReasonScanBudget,
			wantComplete:   database.CompletenessPartial,
			wantStopReason: database.ReasonScanBudget,
		},
		{
			// A stop reason alone is enough: the loop stopped launching work, so
			// the plan was not finished even if every phase that ran was clean.
			name: "stop reason with clean phases",
			phases: []database.PhaseOutcome{
				{Phase: "discovery", State: database.PhaseCompleted},
			},
			stopReason:     database.ReasonCancelled,
			wantComplete:   database.CompletenessPartial,
			wantStopReason: database.ReasonCancelled,
		},
		{
			name:         "no phases at all",
			wantComplete: database.CompletenessComplete,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runner{}
			for _, p := range tc.phases {
				r.scanOutcome.append(p)
			}
			r.scanOutcome.setStopReason(tc.stopReason)

			got := r.Completion()
			if got.Completeness != tc.wantComplete {
				t.Errorf("Completeness = %q, want %q", got.Completeness, tc.wantComplete)
			}
			if got.StopReason != tc.wantStopReason {
				t.Errorf("StopReason = %q, want %q", got.StopReason, tc.wantStopReason)
			}
			if len(got.Phases) != len(tc.phases) {
				t.Errorf("Phases = %d, want %d", len(got.Phases), len(tc.phases))
			}
		})
	}
}

// TestScanOutcomeResetClearsPriorRun pins the agent-rescan case: a Runner is
// reused, and inheriting the previous run's phase list would stamp the earlier
// scan's curtailment on the later scan's row.
func TestScanOutcomeResetClearsPriorRun(t *testing.T) {
	r := &Runner{}
	r.scanOutcome.append(database.PhaseOutcome{Phase: "discovery", State: database.PhasePartial,
		Reasons: []string{database.ReasonScanBudget}})
	r.scanOutcome.setStopReason(database.ReasonScanBudget)

	r.scanOutcome.reset()

	got := r.Completion()
	if got.Completeness != database.CompletenessComplete || got.StopReason != "" || len(got.Phases) != 0 {
		t.Errorf("reset left state behind: %+v", got)
	}
}

// TestScanOutcomeCoalescesByPhase pins the bound on the ledger.
// full-native-scan-on-receive runs the whole plan once per batch of arriving
// records, so one entry per execution would grow the list — and the
// phase_outcomes column it is serialised into — for the life of the run.
func TestScanOutcomeCoalescesByPhase(t *testing.T) {
	r := &Runner{}
	for i := 0; i < 50; i++ {
		r.scanOutcome.append(database.PhaseOutcome{
			Phase: "discovery", State: database.PhaseCompleted, DurationMS: 10,
		})
		r.scanOutcome.append(database.PhaseOutcome{
			Phase: "dynamic-assessment", State: database.PhaseCompleted, DurationMS: 20,
		})
	}
	// One late iteration lost coverage; the aggregate must say so.
	r.scanOutcome.append(database.PhaseOutcome{
		Phase: "discovery", State: database.PhaseFailed,
		Reasons: []string{database.ReasonTargetsFailed}, Errors: 1,
	})

	got := r.Completion()
	if len(got.Phases) != 2 {
		t.Fatalf("Phases = %d, want 2 (one per phase): %+v", len(got.Phases), got.Phases)
	}
	// Insertion order is preserved, so the list still reads in execution order.
	if got.Phases[0].Phase != "discovery" || got.Phases[1].Phase != "dynamic-assessment" {
		t.Errorf("phase order changed: %+v", got.Phases)
	}
	disc := got.Phases[0]
	if disc.State != database.PhaseFailed {
		t.Errorf("discovery State = %q, want failed (one iteration errored)", disc.State)
	}
	if disc.DurationMS != 500 {
		t.Errorf("discovery DurationMS = %d, want 500 (summed)", disc.DurationMS)
	}
	if got.Completeness != database.CompletenessPartial {
		t.Errorf("Completeness = %q, want partial", got.Completeness)
	}
}

// TestScanOutcomeStopReasonKeepsTheFirst: a budget that fires makes every later
// phase skip, so the last reason names the consequence and the first names the
// cause.
func TestScanOutcomeStopReasonKeepsTheFirst(t *testing.T) {
	var s scanOutcome
	s.setStopReason(database.ReasonScanBudget)
	s.setStopReason(database.ReasonCancelled)
	if _, reason := s.snapshot(); reason != database.ReasonScanBudget {
		t.Errorf("stopReason = %q, want the first one set", reason)
	}
}

func TestRecordSkippedSteps(t *testing.T) {
	r := &Runner{}
	r.recordSkippedSteps([]NativePhaseStep{
		{Phase: PhaseKnownIssueScan, Enabled: true},
		{Phase: PhaseTargetedReSpider, Enabled: false},
		{Phase: PhaseDynamicAssessment, Enabled: true},
	}, database.ReasonScanBudget)

	got := r.Completion()
	if got.Completeness != database.CompletenessPartial {
		t.Errorf("Completeness = %q, want partial", got.Completeness)
	}
	if got.StopReason != database.ReasonScanBudget {
		t.Errorf("StopReason = %q", got.StopReason)
	}
	// The disabled step is not a gap — it was never going to run.
	if len(got.Phases) != 2 {
		t.Fatalf("Phases = %d, want 2 (the enabled ones): %+v", len(got.Phases), got.Phases)
	}
	for _, p := range got.Phases {
		if p.State != database.PhaseSkipped {
			t.Errorf("%s: State = %q, want skipped", p.Phase, p.State)
		}
		if !reflect.DeepEqual(p.Reasons, []string{database.ReasonScanBudget}) {
			t.Errorf("%s: Reasons = %v", p.Phase, p.Reasons)
		}
	}
}

func TestPartialBannerSuffix(t *testing.T) {
	if got := partialBannerSuffix(database.ScanCompletion{Completeness: database.CompletenessComplete}); got != "" {
		t.Errorf("a complete scan must add nothing, got %q", got)
	}

	got := partialBannerSuffix(database.ScanCompletion{
		Completeness: database.CompletenessPartial,
		StopReason:   database.ReasonScanBudget,
		Phases: []database.PhaseOutcome{
			{Phase: "discovery", State: database.PhaseCompleted},
			{Phase: "dynamic-assessment", State: database.PhasePartial,
				Reasons: []string{database.ReasonPhaseDeadline, database.ReasonPersistence}},
			{Phase: "known-issue-scan", State: database.PhaseSkipped,
				Reasons: []string{database.ReasonScanBudget}},
		},
	})
	for _, want := range []string{
		"partial",
		"dynamic-assessment(phase_deadline,persistence_incomplete)",
		"known-issue-scan(scan_budget)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("banner suffix %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "discovery") {
		t.Errorf("a clean phase must not be named: %q", got)
	}
}

// TestPartialBannerSuffixFallsBackToStopReason covers the shape the
// full-scan-on-receive loop can produce: a stop reason with no phase carrying a
// reason of its own. The line must still say something.
func TestPartialBannerSuffixFallsBackToStopReason(t *testing.T) {
	got := partialBannerSuffix(database.ScanCompletion{
		Completeness: database.CompletenessPartial,
		StopReason:   database.ReasonCancelled,
		Phases: []database.PhaseOutcome{
			{Phase: "discovery", State: database.PhaseCompleted},
		},
	})
	if !strings.Contains(got, database.ReasonCancelled) {
		t.Errorf("suffix = %q, want it to name the stop reason", got)
	}
}

// TestTrackerConcurrentMarks exercises the lock under the conditions the marks
// actually arrive in: a deadline cancel func, a worker teardown and a deferred
// writer shutdown all run on different goroutines while the phase goroutine
// reads the ledger.
func TestTrackerConcurrentMarks(t *testing.T) {
	tr := newLedger("dynamic-assessment")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tr.markPartial(database.ReasonPhaseDeadline)
			tr.noteLimit(database.LimitTargetBudget)
			tr.noteExecution(core.ExecutionReport{StoppedEarly: true, Unacked: 1})
			tr.addPersistence(database.PersistenceOutcome{Accepted: 1, Failed: 1})
			tr.noteError(errString("boom"))
			_ = tr.outcome()
		}(i)
	}
	wg.Wait()

	out := tr.finish(context.Background(), nil)
	if out.Errors != 8 {
		t.Errorf("Errors = %d, want 8", out.Errors)
	}
	if out.Unprocessed != 8 {
		t.Errorf("Unprocessed = %d, want 8", out.Unprocessed)
	}
	if out.Persistence == nil || out.Persistence.Failed != 8 {
		t.Errorf("Persistence = %+v, want 8 failed", out.Persistence)
	}
}

func TestDynamicAssessmentExitLine(t *testing.T) {
	// The old line claimed "all rounds completed" on every path, including the
	// one case it was certainly wrong about.
	if got := dynamicAssessmentExitLine(2, time.Second, errString("boom"), false); !strings.Contains(got, "round 2 error") {
		t.Errorf("error exit = %q", got)
	}
	if got := dynamicAssessmentExitLine(3, time.Second, nil, true); !strings.Contains(got, "phase deadline after 3") {
		t.Errorf("deadline exit = %q", got)
	}
	if got := dynamicAssessmentExitLine(1, time.Second, nil, false); !strings.Contains(got, "completed 1 round") {
		t.Errorf("clean exit = %q", got)
	}
}

// errString is a minimal error so the tests do not depend on fmt.Errorf's
// formatting when they assert on a stored message.
type errString string

func (e errString) Error() string { return string(e) }

func hasReason(out database.PhaseOutcome, reason string) bool {
	for _, r := range out.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}

// TestTrackerAuthUnavailable: a scan that could not apply its configured
// authentication is PARTIAL, not completed. The generic auth_unavailable code
// is always present so a consumer has one thing to match on, and the specific
// cause rides alongside it.
func TestTrackerAuthUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		specific string
		want     []string
	}{
		{"generic failure", "", []string{database.ReasonAuthUnavailable}},
		{"login budget", database.ReasonLoginBudget, []string{database.ReasonAuthUnavailable, database.ReasonLoginBudget}},
		{"cancelled", database.ReasonCancelled, []string{database.ReasonAuthUnavailable, database.ReasonCancelled}},
		{"same code twice", database.ReasonAuthUnavailable, []string{database.ReasonAuthUnavailable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newLedger("dynamic-assessment")
			tr.markPartial(database.ReasonAuthUnavailable)
			if tc.specific != "" {
				tr.markPartial(tc.specific)
			}
			out := tr.finish(context.Background(), nil)
			if out.State != database.PhasePartial {
				t.Errorf("State = %q, want partial", out.State)
			}
			if !reflect.DeepEqual(out.Reasons, tc.want) {
				t.Errorf("Reasons = %v, want %v", out.Reasons, tc.want)
			}
		})
	}
}

// TestFirstPhaseReason_SkipsNonStoppingReasons: reasons within a phase are
// sorted, so `auth_unavailable` sorts ahead of `scan_budget` — but it never
// stopped anything, and reporting it as the scan's stop_reason tells an operator
// the wrong thing about why the scan ended.
func TestFirstPhaseReason_SkipsNonStoppingReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		phases []database.PhaseOutcome
		want   string
	}{
		{
			name: "a real stop reason outranks the caveat",
			phases: []database.PhaseOutcome{
				{Phase: "seed", State: database.PhaseCompleted},
				{Phase: "dynamic-assessment", State: database.PhasePartial,
					Reasons: []string{database.ReasonAuthUnavailable, database.ReasonScanBudget}},
			},
			want: database.ReasonScanBudget,
		},
		{
			name: "the caveat alone is still reported",
			phases: []database.PhaseOutcome{
				{Phase: "dynamic-assessment", State: database.PhasePartial,
					Reasons: []string{database.ReasonAuthUnavailable}},
			},
			want: database.ReasonAuthUnavailable,
		},
		{
			name: "a later phase's real reason outranks an earlier caveat",
			phases: []database.PhaseOutcome{
				{Phase: "dynamic-assessment", State: database.PhasePartial,
					Reasons: []string{database.ReasonAuthUnavailable}},
				{Phase: "known-issue-scan", State: database.PhaseSkipped,
					Reasons: []string{database.ReasonCancelled}},
			},
			want: database.ReasonCancelled,
		},
		{
			// oast_unavailable sorts ahead of phase_deadline, but out-of-band
			// checks being off never stopped the scan.
			name: "oast_unavailable is a caveat, not a stop reason",
			phases: []database.PhaseOutcome{
				{Phase: "dynamic-assessment", State: database.PhasePartial,
					Reasons: []string{database.ReasonOASTUnavailable, database.ReasonPhaseDeadline}},
			},
			want: database.ReasonPhaseDeadline,
		},
		{
			name: "a failed phase with no reasons still reports error",
			phases: []database.PhaseOutcome{
				{Phase: "discovery", State: database.PhaseFailed},
			},
			want: database.ReasonError,
		},
		{
			name:   "nothing to report",
			phases: []database.PhaseOutcome{{Phase: "probe", State: database.PhaseCompleted}},
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstPhaseReason(tc.phases); got != tc.want {
				t.Errorf("firstPhaseReason = %q, want %q", got, tc.want)
			}
		})
	}
}
