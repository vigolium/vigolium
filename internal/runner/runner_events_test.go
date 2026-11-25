package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// withEventStream installs a process event emitter writing into buf, and removes
// it again when the test ends. The emitter is process-global, so a test that
// left one installed would make every later test in the package emit into a dead
// buffer.
func withEventStream(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	scanevents.Install(scanevents.New(&buf, "scan-test"))
	t.Cleanup(func() { scanevents.Install(nil) })
	return &buf
}

// eventsOfType returns the decoded events of one type from an NDJSON buffer.
func eventsOfType(t *testing.T, buf *bytes.Buffer, typ string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("event line is not JSON: %v (%q)", err, line)
		}
		if ev["type"] == typ {
			out = append(out, ev)
		}
	}
	return out
}

// TestPhaseFinishedReportsCurtailedWithReasons is the stream half of the fix: a
// phase that was cut short reports "curtailed" and SAYS WHY. Before, the status
// came from the outer context alone, so a phase stopped by its own deadline — or
// by failed targets, or by lost writes — emitted "completed" with no field a
// consumer could read to learn otherwise.
func TestPhaseFinishedReportsCurtailedWithReasons(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "discovery", nil)
	tr.markPartial(database.ReasonPhaseDeadline)
	tr.noteLimit(database.LimitTargetBudget)
	tr.finish(context.Background(), nil)

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1: %s", len(finished), buf.String())
	}
	ev := finished[0]
	if ev["status"] != scanevents.StatusCurtailed {
		t.Errorf("status = %v, want %q", ev["status"], scanevents.StatusCurtailed)
	}
	reasons, _ := ev["reasons"].([]any)
	if len(reasons) != 1 || reasons[0] != database.ReasonPhaseDeadline {
		t.Errorf("reasons = %v, want [%s]", ev["reasons"], database.ReasonPhaseDeadline)
	}
	limits, _ := ev["limits"].([]any)
	if len(limits) != 1 || limits[0] != database.LimitTargetBudget {
		t.Errorf("limits = %v, want [%s]", ev["limits"], database.LimitTargetBudget)
	}
}

func TestPhaseFinishedCleanRunCarriesNoReasons(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "probe", nil)
	tr.finish(context.Background(), nil)

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1", len(finished))
	}
	ev := finished[0]
	if ev["status"] != scanevents.StatusCompleted {
		t.Errorf("status = %v, want completed", ev["status"])
	}
	// omitempty: a clean phase's line is byte-identical to what it was before
	// these fields existed, so a consumer sees no change.
	if _, ok := ev["reasons"]; ok {
		t.Errorf("reasons present on a clean phase: %v", ev["reasons"])
	}
	if _, ok := ev["limits"]; ok {
		t.Errorf("limits present on a clean phase: %v", ev["limits"])
	}
	if _, ok := ev["stop_reason"]; ok {
		t.Errorf("stop_reason present on a phase event: %v", ev["stop_reason"])
	}
}

// TestPhaseFinishedFailedOutranksCurtailed: a phase that failed must not be
// softened to "curtailed" just because it was also cut short.
func TestPhaseFinishedFailedOutranksCurtailed(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "spidering", nil)
	tr.markPartial(database.ReasonTargetsSkipped)
	tr.finish(context.Background(), errString("spidering blew up"))

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1", len(finished))
	}
	if got := finished[0]["status"]; got != scanevents.StatusFailed {
		t.Errorf("status = %v, want failed", got)
	}
	if got := finished[0]["message"]; got != "spidering blew up" {
		t.Errorf("message = %v", got)
	}
}

// TestPhaseFinishedSkippedReportsSkipped: a phase that did no work says
// skipped, with the reason attached, so "completed" always means it ran.
func TestPhaseFinishedSkippedReportsSkipped(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "dynamic-assessment", nil)
	tr.markSkipped(database.ReasonNoModules)
	tr.finish(context.Background(), nil)

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1", len(finished))
	}
	if got := finished[0]["status"]; got != scanevents.StatusSkipped {
		t.Errorf("status = %v, want skipped", got)
	}
	reasons, _ := finished[0]["reasons"].([]any)
	if len(reasons) != 1 || reasons[0] != database.ReasonNoModules {
		t.Errorf("reasons = %v, want [no_modules]", finished[0]["reasons"])
	}
}

// TestNoteErrorRecordsAndEmits: the `error` event is the non-fatal channel, and
// the ledger must be written whether or not a stream is attached. Both halves
// here, since the recording used to sit behind the stream check.
func TestNoteErrorRecordsAndEmits(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "harvest", nil)
	tr.noteError(errString("archive source refused"))
	out := tr.finish(context.Background(), nil)

	if out.Errors != 1 || out.Message != "archive source refused" {
		t.Errorf("ledger did not record the error: %+v", out)
	}
	errs := eventsOfType(t, buf, scanevents.TypeError)
	if len(errs) != 1 {
		t.Fatalf("got %d error events, want 1: %s", len(errs), buf.String())
	}
	if got := errs[0]["phase"]; got != "harvest" {
		t.Errorf("error event phase = %v", got)
	}
}

// TestOutcomeIdenticalWithStreamOnAndOff pins that the two paths agree. The
// stream and the database used to disagree precisely because only one of them
// was populated.
func TestOutcomeIdenticalWithStreamOnAndOff(t *testing.T) {
	build := func() database.PhaseOutcome {
		r := &Runner{}
		tr := r.beginPhase(context.Background(), "discovery", nil)
		tr.markPartial(database.ReasonTargetsFailed)
		tr.noteLimit(database.LimitTargetBudget)
		tr.noteExecution(core.ExecutionReport{StoppedEarly: true, Unacked: 2})
		tr.addPersistence(database.PersistenceOutcome{Accepted: 3, Committed: 2, Failed: 1})
		return tr.finish(context.Background(), nil)
	}

	off := build()
	withEventStream(t)
	on := build()

	// DurationMS is wall-clock and will differ; everything else must match.
	off.DurationMS, on.DurationMS = 0, 0
	if off.State != on.State || off.Unprocessed != on.Unprocessed ||
		strings.Join(off.Reasons, ",") != strings.Join(on.Reasons, ",") ||
		strings.Join(off.Limits, ",") != strings.Join(on.Limits, ",") {
		t.Errorf("outcome differs with the stream on:\n off = %+v\n on  = %+v", off, on)
	}
}

// TestBeginPhaseHeartbeatStopsOnFinish guards the join: finish closes the stop
// channel and waits for the heartbeat goroutine, so no progress line can be
// written after the phase's finished line.
func TestBeginPhaseHeartbeatStopsOnFinish(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "probe", nil)
	tr.finish(context.Background(), nil)

	before := buf.Len()
	time.Sleep(50 * time.Millisecond)
	if buf.Len() != before {
		t.Errorf("the stream grew after finish: %s", buf.String()[before:])
	}
}

// TestAddCounterReachesRequestsSent is the counter half of WP10: a phase whose
// traffic does NOT go through the shared requester — discovery runs deparos,
// which owns its own HTTP client — used to report ≈0 requests for the crawl that
// produced every record it emitted.
func TestAddCounterReachesRequestsSent(t *testing.T) {
	buf := withEventStream(t)

	var sent atomic.Int64
	r := &Runner{}
	tr := r.beginPhase(context.Background(), "discovery", nil)
	tr.addCounter(sent.Load)
	sent.Store(1234)
	tr.finish(context.Background(), nil)

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1: %s", len(finished), buf.String())
	}
	if got := finished[0]["requests_sent"]; got != float64(1234) {
		t.Fatalf("requests_sent = %v, want 1234", got)
	}
}

// TestAddCounterIsBaselinedAtRegistration pins that only traffic from the
// registration point forward is attributed to the phase. A counter whose owner
// was already busy (a reused source, a mid-scan phase-local requester) must not
// hand the phase someone else's requests.
func TestAddCounterIsBaselinedAtRegistration(t *testing.T) {
	buf := withEventStream(t)

	var sent atomic.Int64
	sent.Store(500) // traffic from before this phase began

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "discovery", nil)
	tr.addCounter(sent.Load)
	sent.Store(530)
	tr.finish(context.Background(), nil)

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1", len(finished))
	}
	if got := finished[0]["requests_sent"]; got != float64(30) {
		t.Fatalf("requests_sent = %v, want 30 (the delta, not the absolute count)", got)
	}
}

func TestAddCounterSumsSeveralAndIsNilSafe(t *testing.T) {
	var a, b atomic.Int64
	r := &Runner{}
	tr := r.beginPhase(context.Background(), "discovery", nil)
	tr.addCounter(a.Load)
	tr.addCounter(b.Load)
	tr.addCounter(nil) // must not panic or register anything
	a.Store(7)
	b.Store(11)
	if got := tr.sentSoFar(); got != 18 {
		t.Fatalf("sentSoFar = %d, want 18", got)
	}

	var nilTracker *phaseTracker
	nilTracker.addCounter(a.Load) // must not panic
}

// TestAddCounterConcurrentWithHeartbeat is the -race case: addCounter is called
// from the phase goroutine while the heartbeat goroutine reads the same slice.
func TestAddCounterConcurrentWithHeartbeat(t *testing.T) {
	withEventStream(t)

	var sent atomic.Int64
	r := &Runner{}
	tr := r.beginPhase(context.Background(), "discovery", nil)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.addCounter(sent.Load)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tr.sentSoFar()
		}()
	}
	wg.Wait()
	sent.Store(3)
	if got := tr.sentSoFar(); got != 8*3 {
		t.Fatalf("sentSoFar = %d, want %d (8 counters x 3)", got, 8*3)
	}
	tr.finish(context.Background(), nil)
}
