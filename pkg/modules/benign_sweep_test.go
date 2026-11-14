package modules

import (
	"encoding/json"
	"flag"
	"fmt"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// The benign sweep (MEAS-3 + MEAS-4) runs every registered active module
// against every benign fixture (pkg/modules/modtest/fixtures.go) with a query
// record and a JSON-body record, and asserts:
//
//  1. no finding above Info - a false positive on a server with no
//     vulnerability - unless the module/fixture pair is allow-listed below;
//  2. on deterministic fixtures, the module's request count stays within ±25%
//     (at least ±2) of the golden budget in testdata/request_budget.json.
//     After an intended change, regenerate it:
//     go test ./pkg/modules/ -run 'TestBenignSweep$' -args -update-request-budget
//
// The slow_host fixture runs only for timing modules and only without -short.

var updateRequestBudget = flag.Bool("update-request-budget", false,
	"rewrite pkg/modules/testdata/request_budget.json from this run")

const (
	requestBudgetFile = "testdata/request_budget.json"
	// requestBudgetTolerance is the allowed relative drift from the golden
	// count; requestBudgetSlack the absolute drift allowed for tiny budgets.
	requestBudgetTolerance = 0.25
	requestBudgetSlack     = 2
)

// timingModules are the modules whose oracle is response time; they are the
// only ones swept against slow_host.
var timingModules = []string{
	"sqli-time-blind",
	"command-injection-timing",
	"ssti-blind",
	"nosqli-operator-injection",
	"redos-probe",
	"server-side-js-injection",
}

// benignSweepSkip lists modules the sweep does not run, with the reason.
var benignSweepSkip = map[string]string{
	// Drives headless Chromium per call; against loopback fixtures that is
	// minutes of browser launch/settle per cell. Covered by its own tests.
	"xss-dom-confirm": "drives a headless browser per call (minutes per cell)",
}

// benignSweepAllowList maps "module/fixture" (fixture "*" for every fixture)
// to why the module may report above Info against that benign fixture. Each
// entry is a known false positive to fix; TestBenignSweepAllowListIsCurrent
// fails when an entry stops firing.
var benignSweepAllowList = map[string]string{
	// Single-session neighbour-ID diff: the fixture echoes the JSON body, so
	// id=12 and id=13 differ and the module files Medium/Tentative IDOR. RES-7
	// (Track B) moves it to Suspect/Tentative, which is still above Info; the
	// real fix is requiring a second principal or object-shaped user fields.
	"idor-detection/safe_echo":      "single-session neighbour-ID diff fires on an echoing JSON endpoint (RES-7 follow-up)",
	"idor-detection/soft_404":       "single-session neighbour-ID diff fires on an echoing JSON endpoint (RES-7 follow-up)",
	"idor-detection/rate_limit_429": "single-session neighbour-ID diff fires on an echoing JSON endpoint before the limiter engages (RES-7 follow-up)",
}

// sweepShapes are the request shapes each module sees per fixture.
var sweepShapes = []struct {
	name  string
	build func(t testing.TB, base string) *httpmsg.HttpRequestResponse
}{
	{"query", func(t testing.TB, base string) *httpmsg.HttpRequestResponse {
		return modtest.Request(t, base+"/search?q=shoes&id=12&page=2")
	}},
	{"json", func(t testing.TB, base string) *httpmsg.HttpRequestResponse {
		return modtest.RequestJSON(t, base+"/api/items", `{"name":"shoes","id":12,"filter":{"color":"red"}}`)
	}},
}

type sweepCell struct{ module, fixture, shape string }

func (c sweepCell) key() string { return c.module + "|" + c.fixture + "|" + c.shape }

type sweepResult struct {
	findings      []string // findings above Info
	requests      int64
	deterministic bool
}

func allowListed(moduleID, fixture string) bool {
	if _, ok := benignSweepAllowList[moduleID+"/"+fixture]; ok {
		return true
	}
	_, ok := benignSweepAllowList[moduleID+"/*"]
	return ok
}

// runBenignSweep runs the sweep once per test binary and caches the results:
// TestBenignSweep and TestBenignSweepAllowListIsCurrent share them.
var (
	sweepOnce    sync.Once
	sweepResults map[sweepCell]sweepResult
)

func runBenignSweep(t *testing.T) map[sweepCell]sweepResult {
	t.Helper()
	sweepOnce.Do(func() {
		sweepResults = make(map[sweepCell]sweepResult)
		var mu sync.Mutex
		// One requester (and so one host limiter) per fixture, with the
		// 429/503 host pause off: every fixture listens on 127.0.0.1, and the
		// 429 fixture's Retry-After would otherwise pace every module of the
		// sweep at one request a second. The sweep asserts what modules
		// conclude, not how the limiter paces.
		clients := make(map[string]*httpRequester.Requester)
		for _, fx := range modtest.BenignFixtures() {
			clients[fx.Name] = modtest.RequesterNoThrottlePause(t)
		}

		t.Run("sweep", func(t *testing.T) {
			for _, mod := range DefaultRegistry.GetActiveModules() {
				if _, skip := benignSweepSkip[mod.ID()]; skip {
					continue
				}
				t.Run(mod.ID(), func(t *testing.T) {
					t.Parallel()
					for _, fx := range modtest.BenignFixtures() {
						if fx.TimingOnly && (testing.Short() || !slices.Contains(timingModules, mod.ID())) {
							continue
						}
						for _, shape := range sweepShapes {
							srv := modtest.Serve(t, fx.New())
							rr := shape.build(t, srv.URL)
							if !mod.CanProcess(rr) {
								continue
							}
							var sent atomic.Int64
							scanCtx := &modkit.ScanContext{
								TechStack:     modkit.NewTechRegistry(),
								OASTProvider:  &modtest.MockOASTProvider{},
								ParamFindings: &modkit.ParameterFindingRegistry{},
							}
							// Module errors are not failures here: a benign
							// fixture may legitimately make a probe error out.
							client := clients[fx.Name]
							if fx.Throttles {
								// The throttle streak is per host: a requester
								// shared across parallel modules would make each
								// module's retry count depend on the others.
								client = modtest.RequesterNoThrottlePause(t)
							}
							events, _ := modtest.RunActive(mod, rr, client.WithCall(nil, &sent), scanCtx)
							res := sweepResult{requests: sent.Load(), deterministic: fx.Deterministic}
							for _, ev := range events {
								if ev == nil || !ev.IsFinding() || ev.Info.Severity <= severity.Info {
									continue
								}
								res.findings = append(res.findings, describeFinding(ev))
							}
							mu.Lock()
							sweepResults[sweepCell{mod.ID(), fx.Name, shape.name}] = res
							mu.Unlock()
						}
					}
				})
			}
		})
	})
	return sweepResults
}

func describeFinding(ev *output.ResultEvent) string {
	return fmt.Sprintf("%s/%s: %s @ %s", ev.Info.Severity, ev.Info.Confidence, ev.Info.Name, ev.Matched)
}

func sortedCells(results map[sweepCell]sweepResult) []sweepCell {
	cells := slices.Collect(maps.Keys(results))
	slices.SortFunc(cells, func(a, b sweepCell) int {
		switch {
		case a.key() < b.key():
			return -1
		case a.key() > b.key():
			return 1
		}
		return 0
	})
	return cells
}

func TestBenignSweep(t *testing.T) {
	results := runBenignSweep(t)
	if len(results) == 0 {
		t.Fatal("benign sweep produced no results")
	}
	for _, c := range sortedCells(results) {
		if r := results[c]; len(r.findings) > 0 && !allowListed(c.module, c.fixture) {
			t.Errorf("false positive: %s on benign fixture %s (%s shape):\n  %v", c.module, c.fixture, c.shape, r.findings)
		}
	}
	checkRequestBudget(t, results)
}

// TestBenignSweepAllowListIsCurrent keeps the allow-list and skip list honest:
// an entry for a module that no longer exists, or a pair that no longer fires,
// is stale.
func TestBenignSweepAllowListIsCurrent(t *testing.T) {
	results := runBenignSweep(t)
	fires := make(map[string]bool)
	for c, r := range results {
		if len(r.findings) > 0 {
			fires[c.module+"/"+c.fixture] = true
			fires[c.module+"/*"] = true
		}
	}
	for entry, reason := range benignSweepAllowList {
		if reason == "" {
			t.Errorf("allow-list entry %s has no reason", entry)
		}
		if !fires[entry] {
			t.Errorf("stale allow-list entry %s (%s): it no longer fires; remove it", entry, reason)
		}
	}
	for id, reason := range benignSweepSkip {
		if reason == "" || len(GetActiveModulesByIDs([]string{id})) != 1 {
			t.Errorf("skip entry %s is stale or has no reason", id)
		}
	}
	for _, id := range timingModules {
		if len(GetActiveModulesByIDs([]string{id})) != 1 {
			t.Errorf("timingModules lists unknown module %s", id)
		}
	}
}

// checkRequestBudget compares each deterministic cell's request count with the
// golden budget, or rewrites the golden file under -update-request-budget.
func checkRequestBudget(t *testing.T, results map[sweepCell]sweepResult) {
	t.Helper()
	got := make(map[string]int64)
	for c, r := range results {
		if r.deterministic {
			got[c.key()] = r.requests
		}
	}

	if *updateRequestBudget {
		data, err := json.MarshalIndent(got, "", "  ") // map keys are sorted
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(requestBudgetFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(requestBudgetFile, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d request budgets to %s", len(got), requestBudgetFile)
		return
	}

	want := loadRequestBudget(t)
	if want == nil {
		t.Fatalf("%s missing: run `go test ./pkg/modules/ -run 'TestBenignSweep$' -args -update-request-budget`", requestBudgetFile)
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		w, ok := want[k]
		if !ok {
			t.Errorf("request budget: no golden entry for %s (sent %d); regenerate with -update-request-budget", k, got[k])
			continue
		}
		if !withinBudget(got[k], w) {
			t.Errorf("request budget: %s sent %d requests, golden %d (±%.0f%%); if intended, regenerate with -update-request-budget",
				k, got[k], w, requestBudgetTolerance*100)
		}
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("request budget: golden entry %s was not exercised (module removed or no longer processes the record); regenerate", k)
		}
	}
}

func withinBudget(got, want int64) bool {
	allowed := math.Max(float64(want)*requestBudgetTolerance, requestBudgetSlack)
	return math.Abs(float64(got-want)) <= allowed
}

func loadRequestBudget(t *testing.T) map[string]int64 {
	t.Helper()
	data, err := os.ReadFile(requestBudgetFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]int64
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse %s: %v", requestBudgetFile, err)
	}
	return m
}

func TestWithinBudget(t *testing.T) {
	cases := []struct {
		got, want int64
		ok        bool
	}{
		{100, 100, true}, {125, 100, true}, {126, 100, false}, {75, 100, true}, {74, 100, false},
		{3, 1, true}, {4, 1, false}, {0, 0, true}, {2, 0, true}, {3, 0, false},
	}
	for _, c := range cases {
		if withinBudget(c.got, c.want) != c.ok {
			t.Errorf("withinBudget(%d, %d) = %v, want %v", c.got, c.want, !c.ok, c.ok)
		}
	}
}
