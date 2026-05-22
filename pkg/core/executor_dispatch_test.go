package core

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// --- Active-module stubs for dispatch-helper tests ---

// activeStub implements modules.ActiveModule. canProc is returned by CanProcess,
// and procCalls (when set) counts how often CanProcess is invoked — used to
// prove the eligibility cache skips redundant CanProcess calls.
type activeStub struct {
	id        string
	scopes    modules.ScanScope
	canProc   bool
	procCalls *atomic.Int32
}

func (m *activeStub) ID() string                      { return m.id }
func (m *activeStub) Name() string                    { return m.id }
func (m *activeStub) Description() string             { return "" }
func (m *activeStub) ShortDescription() string        { return "" }
func (m *activeStub) ConfirmationCriteria() string    { return "" }
func (m *activeStub) Severity() severity.Severity     { return 0 }
func (m *activeStub) Confidence() severity.Confidence { return 0 }
func (m *activeStub) ScanScopes() modules.ScanScope   { return m.scopes }
func (m *activeStub) Tags() []string                  { return nil }
func (m *activeStub) AllowedInsertionPointTypes() modules.InsertionPointTypeSet {
	return modules.AllInsertionPointTypes
}
func (m *activeStub) CanProcess(_ *httpmsg.HttpRequestResponse) bool {
	if m.procCalls != nil {
		m.procCalls.Add(1)
	}
	return m.canProc
}
func (m *activeStub) ScanPerInsertionPoint(_ *httpmsg.HttpRequestResponse, _ httpmsg.InsertionPoint, _ *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m *activeStub) ScanPerRequest(_ *httpmsg.HttpRequestResponse, _ *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m *activeStub) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// prioritizedActiveStub additionally implements modules.Prioritized.
type prioritizedActiveStub struct {
	activeStub
	priority int
}

func (m *prioritizedActiveStub) Priority() int { return m.priority }

// customCanProcessStub declares that its CanProcess does NOT include the base
// URL/media/method checks, so the executor must still call CanProcess even when
// the base checks fail.
type customCanProcessStub struct {
	activeStub
}

func (m *customCanProcessStub) IncludesBaseCanProcess() bool { return false }

func ids(mods []modules.ActiveModule) []string {
	out := make([]string, len(mods))
	for i, m := range mods {
		out[i] = m.ID()
	}
	return out
}

func TestSortActiveByPriority(t *testing.T) {
	mods := []modules.ActiveModule{
		&activeStub{id: "default-a"}, // no Prioritized → DefaultModulePriority (100)
		&prioritizedActiveStub{activeStub{id: "high"}, 10},
		&prioritizedActiveStub{activeStub{id: "low"}, 200},
		&activeStub{id: "default-b"}, // also 100; must keep registration order vs default-a
	}

	sortActiveByPriority(mods)

	// high(10) < default-a(100) == default-b(100) < low(200); equal priorities
	// keep their relative input order thanks to the stable sort.
	assert.Equal(t, []string{"high", "default-a", "default-b", "low"}, ids(mods))
}

func TestModulePriorityDefault(t *testing.T) {
	assert.Equal(t, modkit.DefaultModulePriority, modulePriority(&activeStub{id: "plain"}))
	assert.Equal(t, 7, modulePriority(&prioritizedActiveStub{activeStub{id: "p"}, 7}))
}

func TestFilterActiveModulesByScanScope(t *testing.T) {
	mods := []modules.ActiveModule{
		&activeStub{id: "req", scopes: modkit.ScanScopeRequest},
		&activeStub{id: "ip", scopes: modkit.ScanScopeInsertionPoint},
		&activeStub{id: "both", scopes: modkit.ScanScopeRequest | modkit.ScanScopeInsertionPoint},
		&activeStub{id: "host", scopes: modkit.ScanScopeHost},
	}

	assert.ElementsMatch(t, []string{"req", "both"},
		ids(filterActiveModulesByScanScope(mods, modules.ScanScopeRequest)))
	assert.ElementsMatch(t, []string{"ip", "both"},
		ids(filterActiveModulesByScanScope(mods, modules.ScanScopeInsertionPoint)))
	assert.ElementsMatch(t, []string{"host"},
		ids(filterActiveModulesByScanScope(mods, modules.ScanScopeHost)))
}

// --- Passive-module stubs for scope-aware filtering ---

type basePassiveStub struct{ id string }

func (m basePassiveStub) ID() string                                     { return m.id }
func (m basePassiveStub) Name() string                                   { return m.id }
func (m basePassiveStub) Description() string                            { return "" }
func (m basePassiveStub) ShortDescription() string                       { return "" }
func (m basePassiveStub) ConfirmationCriteria() string                   { return "" }
func (m basePassiveStub) Severity() severity.Severity                    { return 0 }
func (m basePassiveStub) Confidence() severity.Confidence                { return 0 }
func (m basePassiveStub) ScanScopes() modules.ScanScope                  { return modkit.ScanScopeRequest }
func (m basePassiveStub) Tags() []string                                 { return nil }
func (m basePassiveStub) CanProcess(_ *httpmsg.HttpRequestResponse) bool { return true }
func (m basePassiveStub) Scope() modules.PassiveScanScope                { return modkit.PassiveScanScopeBoth }
func (m basePassiveStub) ScanPerRequest(_ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m basePassiveStub) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// scopeAwarePassiveStub implements modules.ScopeAwareModule.
type scopeAwarePassiveStub struct {
	basePassiveStub
	aware bool
}

func (m scopeAwarePassiveStub) ScopeAware() bool { return m.aware }

func TestFilterNonScopeAware(t *testing.T) {
	mods := []modules.PassiveModule{
		basePassiveStub{id: "plain"},                                            // not scope-aware → kept
		scopeAwarePassiveStub{basePassiveStub{id: "aware"}, true},               // scope-aware → dropped
		scopeAwarePassiveStub{basePassiveStub{id: "declared-not-aware"}, false}, // declares false → kept
	}

	out := filterNonScopeAware(mods)
	got := make([]string, len(out))
	for i, m := range out {
		got[i] = m.ID()
	}
	assert.Equal(t, []string{"plain", "declared-not-aware"}, got,
		"only modules whose ScopeAware() reports true should be removed for out-of-scope items")
}

func TestComputeEligibility(t *testing.T) {
	build := func(method, path string) *httpmsg.HttpRequestResponse {
		raw := []byte(method + " " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
		req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("example.com", 443, true), raw)
		return httpmsg.NewHttpRequestResponse(req, nil)
	}

	t.Run("normal GET is eligible", func(t *testing.T) {
		assert.True(t, computeEligibility(build("GET", "/users?id=1")).baseEligible)
	})
	t.Run("media URL is not eligible", func(t *testing.T) {
		assert.False(t, computeEligibility(build("GET", "/assets/logo.png")).baseEligible)
	})
	t.Run("skipped methods are not eligible", func(t *testing.T) {
		for _, method := range []string{"OPTIONS", "HEAD", "CONNECT", "TRACE"} {
			assert.False(t, computeEligibility(build(method, "/")).baseEligible, "%s should be ineligible", method)
		}
	})
	t.Run("nil item is not eligible", func(t *testing.T) {
		assert.False(t, computeEligibility(nil).baseEligible)
	})
}

func TestActiveModuleCanProcess(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("example.com", 443, true), raw)
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	t.Run("base eligible still calls CanProcess", func(t *testing.T) {
		calls := &atomic.Int32{}
		m := &activeStub{id: "m", canProc: true, procCalls: calls}
		got := activeModuleCanProcess(m, rr, &requestEligibility{baseEligible: true})
		assert.True(t, got)
		assert.Equal(t, int32(1), calls.Load(), "CanProcess must run when base checks pass")
	})

	t.Run("base ineligible skips CanProcess for standard modules", func(t *testing.T) {
		calls := &atomic.Int32{}
		m := &activeStub{id: "m", canProc: true, procCalls: calls}
		got := activeModuleCanProcess(m, rr, &requestEligibility{baseEligible: false})
		assert.False(t, got, "module that includes base checks must be rejected without re-running CanProcess")
		assert.Equal(t, int32(0), calls.Load(), "CanProcess must be skipped when base would reject")
	})

	t.Run("base ineligible still calls custom CanProcess", func(t *testing.T) {
		calls := &atomic.Int32{}
		m := &customCanProcessStub{activeStub{id: "m", canProc: true, procCalls: calls}}
		got := activeModuleCanProcess(m, rr, &requestEligibility{baseEligible: false})
		assert.True(t, got, "module with custom CanProcess must still be consulted")
		assert.Equal(t, int32(1), calls.Load())
	})
}
