//go:build e2e

package e2eexpect

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

// Invariants every scenario can check after a run, whatever it was testing.

// TestMain fails the suite if anything the scans started is still running
// once every test (and its runner and lab) has been torn down. On top of
// modtest's standard ignores (process-lifetime singletons):
func TestMain(m *testing.M) {
	modtest.VerifyNoLeaks(m,
		// jstangle.DefaultService: the process-wide JS-analysis worker pool
		// discovery starts (subprocess workers + their exec watchers).
		goleak.IgnoreAnyFunction("github.com/vigolium/vigolium/pkg/deparos/jstangle.(*WorkerPool).startWorker.func1"),
		goleak.IgnoreTopFunction("os/exec.(*Cmd).watchCtx"),
		// KNOWN ISSUE scan/abandoned-module-goroutines (knownDefects): when a
		// scan is cancelled (request budget, Close), runActiveWithTimeout
		// abandons module goroutines still running; xss-light's browser
		// confirmation keeps launching headless Chrome after RunNativeScan has
		// returned. Delete these once that is fixed — goleak then guards it.
		goleak.IgnoreAnyFunction("github.com/vigolium/vigolium/pkg/modules/active/xss_light_scanner.browserConfirm"),
		goleak.IgnoreAnyFunction("github.com/vigolium/vigolium/pkg/modules/active/xss_light_scanner.acquireProbe"),
		goleak.IgnoreAnyFunction("github.com/vigolium/vigolium/pkg/spitolas.ProbeURL.func1"),
		goleak.IgnoreAnyFunction("github.com/vigolium/vigolium/pkg/spitolas/internal/browser.(*Browser).awaitProcessExit.func1"),
		goleak.IgnoreAnyFunction("github.com/go-rod/rod/lib/launcher.(*Launcher).Launch.func1"),
		goleak.IgnoreAnyFunction("os/exec.(*Cmd).writerDescriptor.func1"),
		// Idle keep-alive connections the shared dialer's pool still holds.
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}

// requireNoContact asserts a server the scan must not reach got nothing.
func requireNoContact(t *testing.T, l *lab.Lab, server string) {
	t.Helper()
	if n := l.Ledger.Count(server); n > 0 {
		for _, h := range l.Ledger.Hits(server)[:min(n, 5)] {
			t.Logf("  out-of-scope hit: %s %s?%s (Host: %s)", h.Method, h.Path, h.RawQuery, h.Host)
		}
		t.Fatalf("%q is out of scope but received %d request(s)", server, n)
	}
}

// requireQuiesced asserts the scan left nothing in flight at any server: no
// request the scanner abandoned is still holding a connection open.
func requireQuiesced(t *testing.T, l *lab.Lab) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for len(l.Ledger.Open()) > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if open := l.Ledger.Open(); len(open) > 0 {
		for _, h := range open[:min(len(open), 10)] {
			t.Logf("  still open after %s: %s %s %s?%s", time.Since(h.Start).Round(time.Millisecond), h.Server, h.Method, h.Path, h.RawQuery)
		}
		t.Fatalf("%d request(s) still in flight 15s after the scan returned", len(open))
	}
}

// checkStore asserts the store a scan left behind is consistent: every
// finding is in the project, belongs to this scan, and points at HTTP
// records that exist.
func checkStore(t *testing.T, sr *scanRun) {
	t.Helper()
	var refs []string
	for _, f := range sr.findings {
		assert.Equalf(t, database.DefaultProjectUUID, f.ProjectUUID, "finding %s is not in the default project", f.ModuleID)
		assert.NotEmptyf(t, f.ModuleID, "finding with no module: %s", f.URL)
		assert.NotEqualf(t, severity.Undefined, severity.ToSeverity(f.Severity), "finding %s has severity %q", f.ModuleID, f.Severity)
		refs = append(refs, f.HTTPRecordUUIDs...)
	}
	refs = lo.Uniq(refs)
	if len(refs) == 0 {
		return
	}
	recs, err := sr.repo.GetRecordsByUUIDs(context.Background(), refs)
	require.NoError(t, err)
	stored := lo.Map(recs, func(r *database.HTTPRecord, _ int) string { return r.UUID })
	missing, _ := lo.Difference(refs, stored)
	assert.Emptyf(t, missing, "findings reference records that were never stored")
}

// heapWatch samples the heap while a scan runs and reports the peak.
type heapWatch struct {
	peak atomic.Uint64
	stop chan struct{}
	wg   sync.WaitGroup
}

func watchHeap() *heapWatch {
	h := &heapWatch{stop: make(chan struct{})}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > h.peak.Load() {
				h.peak.Store(ms.HeapInuse)
			}
			select {
			case <-h.stop:
				return
			case <-t.C:
			}
		}
	}()
	return h
}

func (h *heapWatch) Stop() uint64 {
	close(h.stop)
	h.wg.Wait()
	return h.peak.Load()
}

func atLeast(sev string, floor severity.Severity) bool { return severity.ToSeverity(sev) >= floor }

// --- expectation manifest -------------------------------------------------

const expectFile = "testdata/expect.json"

// expectation is a scenario's golden record: what it found, and roughly how
// many requests that took. Regenerate after an intended change with
//
//	go test -tags e2e ./test/e2e-expect/ -run <Test> -args -update-expect
type expectation struct {
	Found    []string `json:"found"`
	Requests int      `json:"requests,omitempty"`
	// Live scenarios: the URL paths a phase must surface and how many
	// records it stored.
	Paths   []string `json:"paths,omitempty"`
	Records int      `json:"records,omitempty"`
}

func loadExpectations(t *testing.T) map[string]expectation {
	t.Helper()
	out := map[string]expectation{}
	b, err := os.ReadFile(expectFile)
	if os.IsNotExist(err) {
		return out
	}
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

// checkExpectation compares a run against its golden entry: the found set
// must match exactly and the request count stay within ±25% (at least ±10).
// With -update-expect the entry is rewritten instead.
func checkExpectation(t *testing.T, name string, found []string, requests int) {
	t.Helper()
	sort.Strings(found)
	if *updateExpect {
		writeExpectation(t, name, expectation{Found: found, Requests: requests})
		return
	}
	want, ok := loadExpectations(t)[name]
	if !ok {
		t.Fatalf("%s has no entry %q; run with -args -update-expect to record one", expectFile, name)
	}
	assert.Equalf(t, want.Found, found, "found set drifted from %s[%s] (regenerate with -update-expect if intended)", expectFile, name)
	slack := max(10, want.Requests/4)
	assert.InDeltaf(t, want.Requests, requests, float64(slack),
		"request count %d drifted more than ±%d from %s[%s]=%d", requests, slack, expectFile, name, want.Requests)
}

func writeExpectation(t *testing.T, name string, e expectation) {
	t.Helper()
	all := loadExpectations(t)
	all[name] = e
	b, err := json.MarshalIndent(all, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll("testdata", 0o755))
	require.NoError(t, os.WriteFile(expectFile, append(b, '\n'), 0o644))
	t.Logf("updated %s[%s]: %d found, %d paths, %d records, %d requests", expectFile, name, len(e.Found), len(e.Paths), e.Records, e.Requests)
}

// checkLiveExpectation compares a run against a live target with its golden
// entry. A live app is not a lab: what one run finds beyond the golden set is
// logged, not failed. What fails is losing ground — a golden finding no longer
// reported, more than a quarter of the golden paths no longer surfaced, or
// fewer than 60% of the golden record count stored. Record live goldens over
// several runs (-update-expect, then -intersect-expect) so they hold only
// what every run agreed on. Live entries carry no request count: a live run's
// volume tracks how fast the app answers.
func checkLiveExpectation(t *testing.T, name string, got expectation) {
	t.Helper()
	sort.Strings(got.Found)
	sort.Strings(got.Paths)
	if *updateExpect {
		writeExpectation(t, name, got)
		return
	}
	if *intersectExpect {
		prev, ok := loadExpectations(t)[name]
		if ok {
			got.Found = lo.Intersect(prev.Found, got.Found)
			got.Paths = lo.Intersect(prev.Paths, got.Paths)
			got.Records = min(prev.Records, got.Records)
		}
		writeExpectation(t, name, got)
		return
	}
	want, ok := loadExpectations(t)[name]
	if !ok {
		t.Fatalf("%s has no entry %q; run with -args -update-expect to record one", expectFile, name)
	}
	missing, extra := lo.Difference(want.Found, got.Found)
	assert.Emptyf(t, missing, "findings in %s[%s] no longer reported", expectFile, name)
	if len(extra) > 0 {
		t.Logf("new findings not in the golden set (add with -update-expect if they are right): %v", extra)
	}
	if len(want.Paths) > 0 {
		missing, extra := lo.Difference(want.Paths, got.Paths)
		assert.LessOrEqualf(t, len(missing), len(want.Paths)/4,
			"%d of %d golden paths in %s[%s] were not surfaced: %v", len(missing), len(want.Paths), expectFile, name, missing)
		if len(missing) > 0 || len(extra) > 0 {
			t.Logf("paths: %d missing %v, %d new", len(missing), missing, len(extra))
		}
	}
	if want.Records > 0 {
		assert.GreaterOrEqualf(t, got.Records, want.Records*6/10,
			"stored %d records, under 60%% of the golden %d in %s[%s]", got.Records, want.Records, expectFile, name)
	}
}
