package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// classedIPStub is a per-insertion-point module with a vuln class. When gate is
// set, its scan blocks until gate closes and then marks the param found (the
// way xss_dom_confirm does) before returning, so the mark is visible the moment
// its active-task slot frees. reached, when set, is closed by CanProcess: the
// executor calls CanProcess right before the dispatch-time dedup check.
type classedIPStub struct {
	activeStub
	class   string
	gate    chan struct{}
	reached chan struct{}
	calls   atomic.Int32
}

func (m *classedIPStub) VulnClass() string { return m.class }

// AllowedInsertionPointTypes keeps the request to exactly one point (the "id"
// query value) so a single active-task slot is held by one task at a time.
func (m *classedIPStub) AllowedInsertionPointTypes() modules.InsertionPointTypeSet {
	return modkit.NewInsertionPointTypeSet(httpmsg.INS_PARAM_URL)
}

func (m *classedIPStub) CanProcess(_ *httpmsg.HttpRequestResponse) bool {
	if m.reached != nil {
		close(m.reached)
	}
	return true
}

func (m *classedIPStub) ScanPerInsertionPoint(item *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, _ *protohttp.Requester, scanCtx *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.calls.Add(1)
	if m.gate != nil {
		<-m.gate
		scanCtx.MarkParamFound(item, ip.Name(), m.class)
	}
	return nil, nil
}

// runQueuedSameClass dispatches two same-class per-IP modules over a request
// with a single query param, with one active-task slot. The first holds the
// slot until the second has passed its dispatch-time check and is queued on
// the semaphore, then marks the param. It returns how often the second ran.
func runQueuedSameClass(t *testing.T, noParamDedup bool) int32 {
	t.Helper()
	reached := make(chan struct{})
	gate := make(chan struct{})
	first := &classedIPStub{activeStub: activeStub{id: "first", scopes: modules.ScanScopeInsertionPoint}, class: "sqli", gate: gate}
	second := &classedIPStub{activeStub: activeStub{id: "second", scopes: modules.ScanScopeInsertionPoint}, class: "sqli", reached: reached}

	e := NewExecutor(ExecutorConfig{Workers: 1, ActiveTaskLimit: 1, NoParamDedup: noParamDedup}, nil,
		[]modules.ActiveModule{first, second}, nil)
	require.Equal(t, []string{"first", "second"}, ids(e.perIPActive))

	_, item := makeTestItem("example.com", "/item?id=1", "<html></html>")
	elig := computeEligibility(item)
	tr := e.newItemTracker(context.Background(), work.NewWithModules(item, nil), false)
	dispatched := make(chan struct{})
	go func() {
		e.runActivePerInsertionPoint(context.Background(), nil, item, &allModulesFilter, &elig, tr, "")
		close(dispatched)
	}()

	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("second module never reached dispatch")
	}
	// Let the dispatcher pass the second module's dispatch-time check (nothing
	// marked yet) and block on the full semaphore.
	time.Sleep(50 * time.Millisecond)
	close(gate)

	<-dispatched
	tr.done()
	<-tr.finished
	assert.Equal(t, int32(1), first.calls.Load())
	return second.calls.Load()
}

func TestRunActivePerIP_QueuedSameClassTaskRechecksBeforeRunning(t *testing.T) {
	assert.Equal(t, int32(0), runQueuedSameClass(t, false),
		"a task queued before a same-class module marked the param must skip when it runs")
}

func TestRunActivePerIP_NoParamDedupRunsEveryModule(t *testing.T) {
	assert.Equal(t, int32(1), runQueuedSameClass(t, true),
		"--no-param-dedup must let every same-class module test the param")
}

func TestRunActivePerIP_DispatchSkipsMarkedParam(t *testing.T) {
	mod := &classedIPStub{activeStub: activeStub{id: "late", scopes: modules.ScanScopeInsertionPoint}, class: "ssti"}
	e := NewExecutor(ExecutorConfig{Workers: 1}, nil, []modules.ActiveModule{mod}, nil)
	_, item := makeTestItem("Example.COM", "/item?id=1", "")
	// Marked through the module-facing helper; the executor must see the same key.
	e.scanCtx.MarkParamFound(item, "id", "ssti")

	elig := computeEligibility(item)
	tr := e.newItemTracker(context.Background(), work.NewWithModules(item, nil), false)
	e.runActivePerInsertionPoint(context.Background(), nil, item, &allModulesFilter, &elig, tr, "")
	tr.done()
	<-tr.finished
	assert.Equal(t, int32(0), mod.calls.Load())
}

func TestProcessResults_MarkUsesModuleKey(t *testing.T) {
	e := &Executor{scanCtx: &modkit.ScanContext{ParamFindings: &modkit.ParameterFindingRegistry{}}}
	mod := &classifiedPassiveModule{trackingPassiveModule: &trackingPassiveModule{id: "m"}}
	e.processResults(context.Background(), []*output.ResultEvent{{
		URL:              "https://example.com/users?id=1",
		FuzzingParameter: "id",
	}}, mod, nil, nil)

	_, item := makeTestItem("example.com", "/users?id=2", "")
	assert.True(t, e.scanCtx.ParamAlreadyFound(item, "id", "xss"),
		"executor post-emit mark and module check must share one key")

	e.scanCtx.NoParamDedup = true
	assert.False(t, e.scanCtx.ParamAlreadyFound(item, "id", "xss"))
}

func TestSortActiveByPriority_OrdersWithinVulnClass(t *testing.T) {
	mk := func(id, class string, cp int) modules.ActiveModule {
		return &classPrioStub{classedIPStub: classedIPStub{activeStub: activeStub{id: id}, class: class}, cp: cp}
	}
	mods := []modules.ActiveModule{
		mk("sqli-time", "sqli", modkit.ClassCostTiming),
		&activeStub{id: "other"},
		mk("ssrf-x", "ssrf", modkit.ClassCostInBand),
		mk("sqli-error", "sqli", modkit.ClassCostInBand),
		mk("sqli-boolean", "sqli", modkit.ClassCostBoolean),
	}
	sortActiveByPriority(mods)
	assert.Equal(t, []string{"sqli-error", "other", "ssrf-x", "sqli-boolean", "sqli-time"}, ids(mods),
		"same-class modules reorder by cost within their own slots; others stay put")
}

type classPrioStub struct {
	classedIPStub
	cp int
}

func (m *classPrioStub) ClassPriority() int { return m.cp }
