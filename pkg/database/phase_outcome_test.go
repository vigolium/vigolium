package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

func TestResolvePhaseState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		errs    int
		reasons []string
		skipped bool
		want    PhaseState
	}{
		{"clean", 0, nil, false, PhaseCompleted},
		{"reason only", 0, []string{ReasonPhaseDeadline}, false, PhasePartial},
		{"error only", 1, nil, false, PhaseFailed},
		// An error outranks everything: a phase that failed is not merely one
		// that came up short, and not merely one that was skipped.
		{"error beats reason", 2, []string{ReasonTargetsFailed}, false, PhaseFailed},
		{"error beats skipped", 1, nil, true, PhaseFailed},
		{"skipped beats reason", 0, []string{ReasonScanBudget}, true, PhaseSkipped},
		{"skipped bare", 0, nil, true, PhaseSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolvePhaseState(tc.errs, tc.reasons, tc.skipped); got != tc.want {
				t.Errorf("ResolvePhaseState(%d, %v, %v) = %q, want %q",
					tc.errs, tc.reasons, tc.skipped, got, tc.want)
			}
		})
	}
}

// TestResolvePhaseState_LimitsDoNotDowngrade pins the one judgment call in the
// vocabulary: reaching a configured bound is designed behaviour, so limits are
// not an input to the state at all. Were they, every correctly time-boxed scan
// would report as degraded and the signal would be worthless.
func TestResolvePhaseState_LimitsDoNotDowngrade(t *testing.T) {
	if got := ResolvePhaseState(0, nil, false); got != PhaseCompleted {
		t.Fatalf("a phase with only limits must be completed, got %q", got)
	}
}

func TestSortedCodes(t *testing.T) {
	if got := SortedCodes(nil); got != nil {
		t.Errorf("SortedCodes(nil) = %v, want nil", got)
	}
	if got := SortedCodes(map[string]struct{}{}); got != nil {
		t.Errorf("SortedCodes(empty) = %v, want nil", got)
	}
	got := SortedCodes(map[string]struct{}{
		ReasonTargetsSkipped: {},
		ReasonCancelled:      {},
		ReasonPhaseDeadline:  {},
	})
	want := []string{ReasonCancelled, ReasonPhaseDeadline, ReasonTargetsSkipped}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SortedCodes = %v, want %v", got, want)
	}
}

func TestTruncateOutcomeMessage(t *testing.T) {
	short := "boom"
	if got := TruncateOutcomeMessage(short); got != short {
		t.Errorf("short message changed: %q", got)
	}

	long := strings.Repeat("a", OutcomeMessageMax+100)
	got := TruncateOutcomeMessage(long)
	if len(got) != OutcomeMessageMax {
		t.Errorf("len = %d, want %d", len(got), OutcomeMessageMax)
	}

	// A multi-byte rune straddling the cut must not be split: the message is
	// persisted and serialised as JSON, and half a rune is invalid UTF-8.
	multi := strings.Repeat("a", OutcomeMessageMax-1) + "é" + "tail"
	got = TruncateOutcomeMessage(multi)
	if !utf8String(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got)
	}
	if len(got) >= len(multi) {
		t.Errorf("message was not truncated: len %d", len(got))
	}
}

func utf8String(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// TestOutcomeCodesCoversEveryConstant is a drift guard. The reason and limit
// codes are persisted on the scan row and emitted on the event stream, so
// OutcomeCodes is the enumeration a consumer reads — a constant added to the
// block above and forgotten here would be a code in the wild that the published
// vocabulary does not mention.
//
// It parses this package's own source rather than using a hand-maintained list,
// because a hand-maintained list is the thing that drifts.
func TestOutcomeCodesCoversEveryConstant(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "outcome.go", nil, 0)
	if err != nil {
		t.Fatalf("parse outcome.go: %v", err)
	}

	declared := make(map[string]string) // identifier → value
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			name := vs.Names[0].Name
			if !strings.HasPrefix(name, "Reason") && !strings.HasPrefix(name, "Limit") {
				continue
			}
			declared[name] = strings.Trim(lit.Value, `"`)
		}
	}
	if len(declared) == 0 {
		t.Fatal("found no Reason*/Limit* constants — the guard is not looking at the right file")
	}

	listed := make(map[string]int, len(OutcomeCodes))
	for _, code := range OutcomeCodes {
		listed[code]++
	}
	for name, value := range declared {
		switch listed[value] {
		case 1:
		case 0:
			t.Errorf("%s (%q) is declared but missing from OutcomeCodes", name, value)
		default:
			t.Errorf("%s (%q) appears %d times in OutcomeCodes, want exactly once", name, value, listed[value])
		}
	}
	if len(OutcomeCodes) != len(declared) {
		t.Errorf("OutcomeCodes has %d entries but %d constants are declared", len(OutcomeCodes), len(declared))
	}
}

// TestOutcomeCodeValuesAreStable pins the wire values. These are persisted and
// emitted, so renaming one silently breaks every consumer that matched on it —
// the rule is add, never rename, and this is what enforces it.
func TestOutcomeCodeValuesAreStable(t *testing.T) {
	want := map[string]string{
		"phase_deadline":         ReasonPhaseDeadline,
		"scan_budget":            ReasonScanBudget,
		"cancelled":              ReasonCancelled,
		"error":                  ReasonError,
		"no_modules":             ReasonNoModules,
		"drain_stalled":          ReasonDrainStalled,
		"workers_abandoned":      ReasonWorkersAbandoned,
		"deferred_flush_skipped": ReasonDeferredFlushSkipped,
		"producer_abandoned":     ReasonProducerAbandoned,
		"targets_failed":         ReasonTargetsFailed,
		"targets_skipped":        ReasonTargetsSkipped,
		"persistence_incomplete": ReasonPersistence,
		"round_error":            ReasonRoundError,
		"checkpoint_failed":      ReasonCheckpointFailed,
		"input_incomplete":       ReasonInputIncomplete,
		"auth_unavailable":       ReasonAuthUnavailable,
		"login_budget":           ReasonLoginBudget,
		"target_budget":          LimitTargetBudget,

		"targets_out_of_scope":       ReasonTargetsOutOfScope,
		"targets_unreachable":        ReasonTargetsUnreachable,
		"oast_unavailable":           ReasonOASTUnavailable,
		"request_budget":             ReasonRequestBudget,
		"auth_lost":                  ReasonAuthLost,
		"phase_error":                ReasonPhaseError,
		"extensions_all_failed":      ReasonExtensionsAllFailed,
		"abandoned":                  ReasonAbandoned,
		"no_targets_in_scope":        ReasonNoTargetsInScope,
		"no_targets_reachable":       ReasonNoTargetsReachable,
		"host_request_budget":        LimitHostRequestBudget,
		"js_request_cap":             LimitJSRequestCap,
		"js_input_over_hard_limit":   LimitJSInputOverHardLimit,
		"js_template_persist_cap":    LimitJSTemplatePersistCap,
		"cdx_max_rows":               LimitCDXMaxRows,
		"sitemap_cap":                LimitSitemapCap,
		"responses_while_logged_out": LimitResponsesWhileLoggedOut,
		"feedback_dropped":           ReasonFeedbackDropped,
		"edge_blocked":               ReasonEdgeBlocked,
		"browser_unavailable":        ReasonBrowserUnavailable,
		"auth_unverified":            ReasonAuthUnverified,
		"user_stopped":               ReasonUserStopped,
		"findings_per_module":        LimitFindingsPerModule,
		"throttled":                  LimitThrottled,
	}
	for literal, constant := range want {
		if literal != constant {
			t.Errorf("code renamed: constant is %q, the published value is %q", constant, literal)
		}
	}
	if len(want) != len(OutcomeCodes) {
		t.Errorf("%d codes pinned here but %d in OutcomeCodes — pin the new one", len(want), len(OutcomeCodes))
	}
}

func TestPhaseStateValues(t *testing.T) {
	// Deliberately distinct from the scan status vocabulary, and persisted, so
	// pinned the same way.
	for state, want := range map[PhaseState]string{
		PhaseCompleted: "completed",
		PhasePartial:   "partial",
		PhaseFailed:    "failed",
		PhaseSkipped:   "skipped",
	} {
		if string(state) != want {
			t.Errorf("PhaseState %q renamed, want %q", state, want)
		}
	}
	if CompletenessComplete != "complete" || CompletenessPartial != "partial" {
		t.Errorf("completeness values renamed: %q / %q", CompletenessComplete, CompletenessPartial)
	}
}

func TestPhaseOutcomeMerge(t *testing.T) {
	t.Run("unions codes and sums counts", func(t *testing.T) {
		o := PhaseOutcome{
			Phase: "discovery", State: PhaseCompleted,
			Reasons: []string{ReasonTargetsFailed}, Limits: []string{LimitTargetBudget},
			Errors: 1, Message: "first failure", Unprocessed: 2, DurationMS: 100,
		}
		o.Merge(PhaseOutcome{
			Phase: "discovery", State: PhasePartial,
			Reasons: []string{ReasonTargetsSkipped, ReasonTargetsFailed},
			Limits:  []string{LimitTargetBudget},
			Errors:  2, Message: "later failure", Unprocessed: 3, DurationMS: 50,
		})

		if o.State != PhasePartial {
			t.Errorf("State = %q, want partial (the worse of the two)", o.State)
		}
		want := []string{ReasonTargetsFailed, ReasonTargetsSkipped}
		if !reflect.DeepEqual(o.Reasons, want) {
			t.Errorf("Reasons = %v, want %v", o.Reasons, want)
		}
		if !reflect.DeepEqual(o.Limits, []string{LimitTargetBudget}) {
			t.Errorf("Limits = %v, want one deduplicated entry", o.Limits)
		}
		if o.Errors != 3 || o.Unprocessed != 5 || o.DurationMS != 150 {
			t.Errorf("counts did not sum: %+v", o)
		}
		// The FIRST failure is normally the cause; later ones are consequences.
		if o.Message != "first failure" {
			t.Errorf("Message = %q, want the first one", o.Message)
		}
	})

	t.Run("state precedence", func(t *testing.T) {
		for _, tc := range []struct{ a, b, want PhaseState }{
			// Skipped ranks lowest: a phase that ran once and was skipped once
			// did run.
			{PhaseSkipped, PhaseCompleted, PhaseCompleted},
			{PhaseCompleted, PhaseSkipped, PhaseCompleted},
			{PhaseSkipped, PhaseSkipped, PhaseSkipped},
			{PhaseCompleted, PhasePartial, PhasePartial},
			{PhasePartial, PhaseCompleted, PhasePartial},
			// A lost phase is the headline whatever the other attempts managed.
			{PhasePartial, PhaseFailed, PhaseFailed},
			{PhaseFailed, PhaseCompleted, PhaseFailed},
		} {
			o := PhaseOutcome{Phase: "p", State: tc.a}
			o.Merge(PhaseOutcome{Phase: "p", State: tc.b})
			if o.State != tc.want {
				t.Errorf("merge(%q, %q) = %q, want %q", tc.a, tc.b, o.State, tc.want)
			}
		}
	})

	t.Run("persistence", func(t *testing.T) {
		o := PhaseOutcome{Phase: "p"}
		o.Merge(PhaseOutcome{Phase: "p", Persistence: &PersistenceOutcome{
			Writer: PersistenceWriterRecords, Accepted: 4, Committed: 4,
		}})
		if o.Persistence == nil || o.Persistence.Accepted != 4 {
			t.Fatalf("Persistence = %+v, want adopted", o.Persistence)
		}
		o.Merge(PhaseOutcome{Phase: "p", Persistence: &PersistenceOutcome{
			Writer: PersistenceWriterRecords, Accepted: 6, Committed: 5, Failed: 1,
		}})
		if o.Persistence.Accepted != 10 || o.Persistence.Failed != 1 {
			t.Errorf("Persistence = %+v, want 10 accepted / 1 failed", o.Persistence)
		}
		// Merging a nil must not drop what is already there.
		o.Merge(PhaseOutcome{Phase: "p"})
		if o.Persistence == nil || o.Persistence.Accepted != 10 {
			t.Errorf("Persistence = %+v after merging a nil", o.Persistence)
		}
	})
}

func TestMergeCodes(t *testing.T) {
	if got := mergeCodes(nil, nil); got != nil {
		t.Errorf("mergeCodes(nil, nil) = %v, want nil", got)
	}
	a := []string{ReasonCancelled}
	// An empty right side returns the left unchanged, without allocating.
	if got := mergeCodes(a, nil); !reflect.DeepEqual(got, a) {
		t.Errorf("mergeCodes(a, nil) = %v, want %v", got, a)
	}
	got := mergeCodes([]string{ReasonTargetsSkipped}, []string{ReasonCancelled, ReasonTargetsSkipped})
	want := []string{ReasonCancelled, ReasonTargetsSkipped}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeCodes = %v, want %v", got, want)
	}
}

// BenignSkip is the one rule behind "does this phase count against the scan's
// coverage", shared by the completeness verdict, the partial banner, and the
// union of reasons on the terminal event.
func TestPhaseOutcomeBenignSkip(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    PhaseOutcome
		want bool
	}{
		{"skipped with no reason", PhaseOutcome{State: PhaseSkipped}, true},
		{"skipped for no_modules", PhaseOutcome{State: PhaseSkipped, Reasons: []string{ReasonNoModules}}, true},
		{"skipped by the budget", PhaseOutcome{State: PhaseSkipped, Reasons: []string{ReasonScanBudget}}, false},
		{"skipped for several reasons", PhaseOutcome{State: PhaseSkipped, Reasons: []string{ReasonNoModules, ReasonCancelled}}, false},
		{"completed", PhaseOutcome{State: PhaseCompleted}, false},
		// A phase that FAILED without recording a reason is the most serious
		// thing that can happen to a phase, reported with no explanation — not
		// a benign skip.
		{"failed with no reason", PhaseOutcome{State: PhaseFailed}, false},
		{"partial with no reason", PhaseOutcome{State: PhasePartial}, false},
	} {
		if got := tc.o.BenignSkip(); got != tc.want {
			t.Errorf("%s: BenignSkip() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestPhaseOutcomeMerge_SumsFindingsCapped: the per-module drop counts sum
// across merged outcomes of one phase and across phases.
func TestPhaseOutcomeMerge_SumsFindingsCapped(t *testing.T) {
	a := PhaseOutcome{Phase: "dynamic-assessment", FindingsCapped: map[string]int64{"m1": 2}}
	a.Merge(PhaseOutcome{Phase: "dynamic-assessment", FindingsCapped: map[string]int64{"m1": 1, "m2": 4}})
	if a.FindingsCapped["m1"] != 3 || a.FindingsCapped["m2"] != 4 {
		t.Fatalf("merged = %v", a.FindingsCapped)
	}
	sum := SumFindingsCapped([]PhaseOutcome{a, {FindingsCapped: map[string]int64{"m2": 1}}})
	if sum["m1"] != 3 || sum["m2"] != 5 {
		t.Fatalf("sum = %v", sum)
	}
}
