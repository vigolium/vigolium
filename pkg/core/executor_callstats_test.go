package core

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/output"
)

// A module call that saw its host throttle it (CallStats.Throttled > 0) and
// found nothing is inconclusive, not clean: it is counted as an
// inconclusive_throttled skip and in the module metrics. A call that found
// something while throttled keeps its finding and is not counted.
func TestRunActiveWithTimeout_ThrottledCallIsInconclusive(t *testing.T) {
	reqClient := newAbandonTestRequester(t)
	_, item := makeTestItem("example.com", "/", "ok")

	run := func(id string, events []*output.ResultEvent) *Executor {
		e := &Executor{
			cfg:           ExecutorConfig{ActiveModuleTimeout: 5 * time.Second},
			moduleMetrics: &stats.ModuleMetrics{},
			moduleSkips:   newModuleSkipLedger(nil, nil),
		}
		_, completed := e.runActiveWithTimeout(context.Background(),
			func(_ context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
				cs := client.CallStats()
				if cs == nil {
					t.Fatal("per-call requester has no CallStats")
				}
				cs.Throttled.Add(2)
				return events, nil
			},
			&fakeActiveModule{id: id}, item, reqClient, func() {}, 0)
		if !completed {
			t.Fatal("expected completed")
		}
		return e
	}

	e := run("throttled-clean", nil)
	if got := e.ModuleSkips()["throttled-clean"][SkipReasonInconclusiveThrottled]; got != 1 {
		t.Fatalf("inconclusive_throttled = %d, want 1", got)
	}
	if got := e.ModuleMetrics()["throttled-clean"].Inconclusive; got != 1 {
		t.Fatalf("metrics Inconclusive = %d, want 1", got)
	}

	finding := &output.ResultEvent{RecordKind: output.RecordKindFinding}
	e = run("throttled-found", []*output.ResultEvent{finding})
	if got := e.ModuleSkips()["throttled-found"][SkipReasonInconclusiveThrottled]; got != 0 {
		t.Fatalf("a call with a finding counted inconclusive (%d)", got)
	}
}

// The skip ledger counts per (module, reason), ignores unknown reasons and is
// safe on a nil receiver (literal test executors carry none).
func TestModuleSkipLedgerSnapshot(t *testing.T) {
	l := newModuleSkipLedger(nil, nil)
	l.note("m", SkipReasonIPType)
	l.note("m", SkipReasonIPType)
	l.note("m", "not-a-reason")
	snap := l.snapshot()
	if snap["m"][SkipReasonIPType] != 2 || len(snap["m"]) != 1 {
		t.Fatalf("snapshot = %v", snap)
	}
	var nilLedger *moduleSkipLedger
	nilLedger.note("m", SkipReasonIPType) // must not panic
}
