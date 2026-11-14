package runner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

func rejectAll() TargetAdmission {
	return TargetAdmission{Rejected: []TargetVerdict{
		{Target: "http://a.test/", Host: "a.test", Rule: config.ScopeRuleHostInclude},
	}}
}

// Some targets refused: the preflight pseudo-phase carries the tally and
// targets_out_of_scope, and the scan is partial for that reason.
func TestAdmissionOutcomePartialRejection(t *testing.T) {
	adm := TargetAdmission{
		Admitted: []string{"http://in.test/"},
		Rejected: []TargetVerdict{{Target: "http://out.test/", Host: "out.test", Rule: config.ScopeRuleHostExclude}},
	}
	o := admissionOutcome(adm)
	if o.Phase != string(PhasePreflight) || o.State != database.PhasePartial {
		t.Fatalf("outcome = %+v, want a partial preflight", o)
	}
	if !reflect.DeepEqual(o.Reasons, []string{database.ReasonTargetsOutOfScope}) {
		t.Errorf("Reasons = %v", o.Reasons)
	}
	want := database.TargetTally{Requested: 2, Admitted: 1, Rejected: []database.TargetIssue{
		{Target: "http://out.test/", Code: config.ScopeRuleHostExclude},
	}}
	if o.Targets == nil || !reflect.DeepEqual(*o.Targets, want) {
		t.Errorf("Targets = %+v, want %+v", o.Targets, want)
	}

	c := completionOf([]database.PhaseOutcome{o, {Phase: string(PhaseDynamicAssessment), State: database.PhaseCompleted}}, "")
	if c.Completeness != database.CompletenessPartial || c.StopReason != database.ReasonTargetsOutOfScope {
		t.Errorf("completion = %s/%s, want partial/%s", c.Completeness, c.StopReason, database.ReasonTargetsOutOfScope)
	}
}

// Every target admitted: the tally is recorded and the scan stays complete.
func TestAdmissionOutcomeAllAdmittedIsComplete(t *testing.T) {
	o := admissionOutcome(TargetAdmission{Admitted: []string{"http://in.test/"}})
	if o.State != database.PhaseCompleted || len(o.Reasons) != 0 {
		t.Fatalf("outcome = %+v, want a clean preflight", o)
	}
	if c := completionOf([]database.PhaseOutcome{o}, ""); c.Completeness != database.CompletenessComplete {
		t.Errorf("completeness = %s, want complete", c.Completeness)
	}
}

// Every target refused: the run stops with no_targets_in_scope, the scan row's
// stop reason, through the same ledger RunNativeScan writes.
func TestAdmissionOutcomeNoneAdmittedStops(t *testing.T) {
	var s scanOutcome
	s.append(admissionOutcome(rejectAll()))
	s.setStopReason(database.ReasonNoTargetsInScope)
	phases, stop := s.snapshot()
	c := completionOf(phases, stop)
	if c.Completeness != database.CompletenessPartial || c.StopReason != database.ReasonNoTargetsInScope {
		t.Errorf("completion = %s/%s, want partial/no_targets_in_scope", c.Completeness, c.StopReason)
	}
	if got := phases[0].Targets; got == nil || got.Requested != 1 || got.Admitted != 0 || len(got.Rejected) != 1 {
		t.Errorf("tally = %+v", got)
	}
}

func TestTargetsRejectedErrorMatchesSentinel(t *testing.T) {
	var err error = &TargetsRejectedError{Admission: rejectAll()}
	if !errors.Is(err, ErrNoTargetsInScope) {
		t.Fatal("TargetsRejectedError must match ErrNoTargetsInScope")
	}
	if msg := err.Error(); !strings.Contains(msg, "http://a.test/ (scope.host.include)") {
		t.Errorf("message %q must name the target and the rule", msg)
	}
	many := make([]TargetVerdict, 7)
	for i := range many {
		many[i] = TargetVerdict{Target: "t", Rule: "r"}
	}
	if got := DescribeRejected(many, 5); !strings.HasSuffix(got, "and 2 more") {
		t.Errorf("DescribeRejected = %q, want a capped list", got)
	}
}

// Admission applies when the targets are the input, and never to
// scan-on-receive or to a custom source the caller did not mark.
func TestRunnerTargetAdmissionApplies(t *testing.T) {
	scope := config.DefaultSettings()
	scope.Scope.Host = config.ScopeRule{Include: []string{"nomatch.example"}}
	adm := &types.TargetAdmission{}
	cases := []struct {
		name  string
		r     *Runner
		apply bool
	}{
		{"runner.New targets", &Runner{settings: scope, targetsAreInput: true, options: &types.Options{Targets: []string{"http://a.test/"}}}, true},
		{"marked custom source", &Runner{settings: scope, options: &types.Options{Targets: []string{"http://a.test/"}, TargetAdmission: adm}}, true},
		{"unmarked custom source", &Runner{settings: scope, options: &types.Options{Targets: []string{"http://a.test/"}}}, false},
		{"scan on receive", &Runner{settings: scope, targetsAreInput: true, options: &types.Options{Targets: []string{"http://a.test/"}, ScanOnReceive: true}}, false},
		{"full scan on receive", &Runner{settings: scope, targetsAreInput: true, options: &types.Options{Targets: []string{"http://a.test/"}, FullNativeScanOnReceive: true}}, false},
		{"no targets", &Runner{settings: scope, targetsAreInput: true, options: &types.Options{}}, false},
		{"no settings", &Runner{targetsAreInput: true, options: &types.Options{Targets: []string{"http://a.test/"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.r.targetAdmission()
			if (got != nil) != tc.apply {
				t.Fatalf("targetAdmission() = %+v, want applied=%v", got, tc.apply)
			}
			if got != nil && !got.NoneAdmitted() {
				t.Errorf("host.include nomatch.example must refuse http://a.test/: %+v", got)
			}
		})
	}
}

// For input that is not a target list, the executor's own count is the signal:
// a run whose every item scope refused, with no answer at all, is partial with
// targets_out_of_scope.
func TestNoteExecutionAllScopeRejected(t *testing.T) {
	tr := newLedger(string(PhaseDynamicAssessment))
	tr.noteExecution(core.ExecutionReport{ScopeRejected: 3})
	out := tr.finish(context.Background(), nil)
	if !reflect.DeepEqual(out.Reasons, []string{database.ReasonTargetsOutOfScope}) {
		t.Errorf("Reasons = %v, want [targets_out_of_scope]", out.Reasons)
	}

	tr = newLedger(string(PhaseDynamicAssessment))
	tr.noteExecution(core.ExecutionReport{ScopeRejected: 3, Responded: 2})
	if out := tr.finish(context.Background(), nil); len(out.Reasons) != 0 {
		t.Errorf("Reasons = %v: a run that reached something is not out of scope", out.Reasons)
	}
}

// Discovered requests dropped past the feedback overflow cap are a coverage
// gap: the phase is partial with feedback_dropped.
func TestNoteExecutionFeedbackDropped(t *testing.T) {
	tr := newLedger(string(PhaseDynamicAssessment))
	tr.noteExecution(core.ExecutionReport{Responded: 1, FeedbackDropped: 2})
	out := tr.finish(context.Background(), nil)
	if !reflect.DeepEqual(out.Reasons, []string{database.ReasonFeedbackDropped}) {
		t.Errorf("Reasons = %v, want [feedback_dropped]", out.Reasons)
	}
}

// Module calls answered by a throttling host with nothing found are a limit
// (throttled), not a degraded phase.
func TestNoteExecutionThrottledLimit(t *testing.T) {
	tr := newLedger(string(PhaseDynamicAssessment))
	tr.noteExecution(core.ExecutionReport{Responded: 1, ModuleSkips: map[string]map[string]int64{
		"sqli_error_based": {core.SkipReasonInconclusiveThrottled: 3},
	}})
	out := tr.finish(context.Background(), nil)
	if len(out.Reasons) != 0 {
		t.Errorf("Reasons = %v, want none", out.Reasons)
	}
	if !reflect.DeepEqual(out.Limits, []string{database.LimitThrottled}) {
		t.Errorf("Limits = %v, want [throttled]", out.Limits)
	}
}
