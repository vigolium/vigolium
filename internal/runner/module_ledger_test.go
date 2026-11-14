package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestModuleLedger_FoldsReportsErrorsAndSkips: the scan's module ledger sums
// every executor report's calls/requests/findings, counts skips by reason, and
// carries errors. A timeout's skip comes from the report only, so the error
// path does not count it a second time.
func TestModuleLedger_FoldsReportsErrorsAndSkips(t *testing.T) {
	l := newModuleErrorLedger()
	round := func(req int64) core.ExecutionReport {
		return core.ExecutionReport{
			ModuleStats: map[string]stats.ModuleStatsSnapshot{"sqli": {Invocations: 2, Requests: req, Findings: 1}},
			ModuleSkips: map[string]map[string]int64{"spring-actuator": {database.SkipTechFilter: 4}},
		}
	}
	timeoutRound := func() core.ExecutionReport {
		return core.ExecutionReport{
			ModuleSkips: map[string]map[string]int64{"sqli": {database.SkipTimeout: 1}},
		}
	}
	l.addExecution(round(10))
	l.addExecution(round(5))
	l.addExecution(timeoutRound())
	l.note("sqli", "timeout")
	l.note("sqli", "exception")

	got := l.moduleStats()
	sqli := got["sqli"]
	if sqli.Invocations != 4 || sqli.Requests != 15 || sqli.Findings != 2 || sqli.Errors != 2 {
		t.Fatalf("sqli = %+v, want 4 calls, 15 requests, 2 findings, 2 errors", sqli)
	}
	if sqli.Skips[database.SkipTimeout] != 1 {
		t.Fatalf("sqli skips = %v, want timeout 1", sqli.Skips)
	}
	if n := got["spring-actuator"].Skips[database.SkipTechFilter]; n != 8 {
		t.Fatalf("tech_filter skips = %d, want 8", n)
	}

	var nilLedger *moduleErrorLedger
	nilLedger.addExecution(round(1))
	if nilLedger.moduleStats() != nil {
		t.Fatal("nil ledger must be inert")
	}
}
