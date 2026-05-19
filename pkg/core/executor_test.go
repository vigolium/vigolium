package core

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/work"
)

func TestModuleFilter(t *testing.T) {
	tests := []struct {
		name          string
		moduleID      string
		enableModules []string
		want          bool
	}{
		{"empty list enables all", "xss", nil, true},
		{"all keyword enables all", "xss", []string{"all"}, true},
		{"exact match", "xss", []string{"xss"}, true},
		{"no match", "xss", []string{"sqli"}, false},
		{"multiple with match", "xss", []string{"sqli", "xss"}, true},
		{"all among others", "xss", []string{"sqli", "all"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := newModuleFilter(tt.enableModules)
			if got := filter.allows(tt.moduleID); got != tt.want {
				t.Errorf("moduleFilter.allows() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModuleFindingAllowed(t *testing.T) {
	t.Run("cap enforced", func(t *testing.T) {
		e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 3}}
		for i := 0; i < 3; i++ {
			if !e.moduleFindingAllowed("test-mod") {
				t.Fatalf("call %d should be allowed", i+1)
			}
		}
		for i := 0; i < 2; i++ {
			if e.moduleFindingAllowed("test-mod") {
				t.Fatalf("call %d past cap should be denied", i+4)
			}
		}
	})

	t.Run("independent modules", func(t *testing.T) {
		e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 1}}
		if !e.moduleFindingAllowed("mod-a") {
			t.Fatal("mod-a first call should be allowed")
		}
		if e.moduleFindingAllowed("mod-a") {
			t.Fatal("mod-a second call should be denied")
		}
		if !e.moduleFindingAllowed("mod-b") {
			t.Fatal("mod-b should be independent and allowed")
		}
	})

	t.Run("cap zero means unlimited", func(t *testing.T) {
		e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 0}}
		for i := 0; i < 100; i++ {
			if !e.moduleFindingAllowed("test-mod") {
				t.Fatalf("call %d should be allowed with cap 0", i+1)
			}
		}
	})
}

// --- Mock passive module for processItem tests ---

type trackingPassiveModule struct {
	id       string
	called   atomic.Int32
	findings []*output.ResultEvent
}

func (m *trackingPassiveModule) ID() string                                     { return m.id }
func (m *trackingPassiveModule) Name() string                                   { return m.id }
func (m *trackingPassiveModule) Description() string                            { return "" }
func (m *trackingPassiveModule) ShortDescription() string                       { return "" }
func (m *trackingPassiveModule) ConfirmationCriteria() string                   { return "" }
func (m *trackingPassiveModule) Severity() severity.Severity                    { return 0 }
func (m *trackingPassiveModule) Confidence() severity.Confidence                { return 0 }
func (m *trackingPassiveModule) ScanScopes() modules.ScanScope                  { return modkit.ScanScopeRequest }
func (m *trackingPassiveModule) Tags() []string                                 { return nil }
func (m *trackingPassiveModule) CanProcess(_ *httpmsg.HttpRequestResponse) bool { return true }
func (m *trackingPassiveModule) Scope() modules.PassiveScanScope {
	return modkit.PassiveScanScopeBoth
}
func (m *trackingPassiveModule) ScanPerRequest(_ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.called.Add(1)
	return m.findings, nil
}
func (m *trackingPassiveModule) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func makeTestItem(host, path, body string) (*work.WorkItem, *httpmsg.HttpRequestResponse) {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure(host, 443, true),
		rawReq,
	)
	rawResp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", body))
	resp := httpmsg.NewHttpResponse(rawResp)
	rr := httpmsg.NewHttpRequestResponse(req, resp)
	item := work.NewWithModules(rr, nil)
	return item, rr
}

// newTestExecutor creates a minimal Executor wired for processItem testing.
// The returned *atomic.Int32 counts OnResult calls.
func newTestExecutor(cfg ExecutorConfig, passiveMods []modules.PassiveModule) (*Executor, *atomic.Int32) {
	var resultCount atomic.Int32
	cfg.OnResult = func(_ *output.ResultEvent) {
		resultCount.Add(1)
	}
	cfg.SkipBaseline = true // response already attached, skip HTTP fetch
	e := &Executor{
		cfg:               cfg,
		passiveModules:    passiveMods,
		perRequestPassive: filterPassiveModulesByScanScope(passiveMods, modules.ScanScopeRequest),
		perHostPassive:    filterPassiveModulesByScanScope(passiveMods, modules.ScanScopeHost),
		requestUUIDs:      newShardedMap(1),
	}
	return e, &resultCount
}

func TestPassiveModulesRunOnScopeFilteredItems(t *testing.T) {
	// Configure a scope matcher that rejects everything via host exclude.
	scopeCfg := *config.DefaultScopeConfig()
	scopeCfg.Host = config.ScopeRule{Include: []string{}, Exclude: []string{"*"}}
	scopeCfg.IgnoreStaticFile = false
	scopeMatcher := config.NewScopeMatcher(scopeCfg)

	passiveMod := &trackingPassiveModule{
		id:       "test-passive",
		findings: []*output.ResultEvent{{URL: "https://example.com/test"}},
	}

	e, resultCount := newTestExecutor(ExecutorConfig{
		ScopeMatcher: scopeMatcher,
	}, []modules.PassiveModule{passiveMod})

	item, _ := makeTestItem("example.com", "/test", "<html>body</html>")
	e.processItem(context.Background(), item)

	if passiveMod.called.Load() == 0 {
		t.Fatal("passive module should have been called despite scope rejection")
	}
	if resultCount.Load() == 0 {
		t.Fatal("passive module findings should have been emitted")
	}
}

func TestPassiveModulesRunOnBodySizeDropItems(t *testing.T) {
	// Configure body size limit that triggers Drop action.
	scopeCfg := *config.DefaultScopeConfig()
	scopeCfg.MaxResponseBodySize = 10
	scopeCfg.BodySizeExceededAction = "drop"
	scopeCfg.IgnoreStaticFile = false
	scopeMatcher := config.NewScopeMatcher(scopeCfg)

	passiveMod := &trackingPassiveModule{
		id:       "test-passive-body",
		findings: []*output.ResultEvent{{URL: "https://example.com/big"}},
	}

	e, resultCount := newTestExecutor(ExecutorConfig{
		ScopeMatcher: scopeMatcher,
	}, []modules.PassiveModule{passiveMod})

	// Body larger than the 10-byte limit
	largeBody := strings.Repeat("A", 100)
	item, _ := makeTestItem("example.com", "/big", largeBody)
	e.processItem(context.Background(), item)

	if passiveMod.called.Load() == 0 {
		t.Fatal("passive module should have been called despite body-size drop")
	}
	if resultCount.Load() == 0 {
		t.Fatal("passive module findings should have been emitted")
	}
}

func TestFeedbackChannel(t *testing.T) {
	// Create a passive module that feeds back a new request via the RequestFeeder
	feedbackMod := &feedbackPassiveModule{
		id: "test-feedback",
	}

	e, resultCount := newTestExecutor(ExecutorConfig{
		Workers:      1,
		SkipBaseline: true,
	}, []modules.PassiveModule{feedbackMod})

	// Initialize feedback channel and scanCtx (newTestExecutor doesn't set these)
	e.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{
		RequestFeeder: &executorFeeder{ch: e.feedbackCh},
	}

	// The feedback module will inject one new item which also gets processed
	item, _ := makeTestItem("example.com", "/trigger", "<html>trigger</html>")

	// Use a simple slice source
	src := &sliceSource{items: []*work.WorkItem{item}}
	e.source = src

	_, err := e.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	// The feedback module is called for the original item, feeds a new item,
	// and then is called again for the fed item. So it should be called >= 2 times.
	calls := feedbackMod.called.Load()
	if calls < 2 {
		t.Errorf("feedback module called %d times, want >= 2 (original + fed item)", calls)
	}

	_ = resultCount
}

func TestParamFindingLocationKeyNormalization(t *testing.T) {
	item, _ := makeTestItem("example.com", "/users?id=1", "<html>body</html>")
	got := paramFindingLocationKeyFromItem(item.Request)
	if got != "https://example.com/users" {
		t.Fatalf("paramFindingLocationKeyFromItem() = %q, want %q", got, "https://example.com/users")
	}

	result := &output.ResultEvent{
		URL:              "https://example.com/users?id=1",
		Matched:          "https://example.com/users?id=1",
		FuzzingParameter: "id",
	}
	if key := paramFindingLocationKeyFromResult(result); key != got {
		t.Fatalf("paramFindingLocationKeyFromResult() = %q, want %q", key, got)
	}
}

func TestContextualPassiveModuleTimeout(t *testing.T) {
	mod := &contextualPassiveModule{id: "contextual-timeout"}
	e, _ := newTestExecutor(ExecutorConfig{
		ScopeMatcher:         nil,
		PassiveModuleTimeout: 20 * time.Millisecond,
	}, []modules.PassiveModule{mod})

	item, _ := makeTestItem("example.com", "/slow", "<html>slow</html>")
	e.processItem(context.Background(), item)

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if mod.cancelled.Load() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("contextual passive module should observe cancellation")
}

// feedbackPassiveModule injects a new request via the feeder on first call.
type feedbackPassiveModule struct {
	id     string
	called atomic.Int32
	fed    atomic.Bool
}

func (m *feedbackPassiveModule) ID() string                                     { return m.id }
func (m *feedbackPassiveModule) Name() string                                   { return m.id }
func (m *feedbackPassiveModule) Description() string                            { return "" }
func (m *feedbackPassiveModule) ShortDescription() string                       { return "" }
func (m *feedbackPassiveModule) ConfirmationCriteria() string                   { return "" }
func (m *feedbackPassiveModule) Severity() severity.Severity                    { return 0 }
func (m *feedbackPassiveModule) Confidence() severity.Confidence                { return 0 }
func (m *feedbackPassiveModule) ScanScopes() modules.ScanScope                  { return modkit.ScanScopeRequest }
func (m *feedbackPassiveModule) Tags() []string                                 { return nil }
func (m *feedbackPassiveModule) CanProcess(_ *httpmsg.HttpRequestResponse) bool { return true }
func (m *feedbackPassiveModule) Scope() modules.PassiveScanScope {
	return modkit.PassiveScanScopeBoth
}
func (m *feedbackPassiveModule) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.called.Add(1)

	// On first call, inject a feedback item
	if m.fed.CompareAndSwap(false, true) {
		feeder := scanCtx.Feeder()
		if feeder != nil {
			service := httpmsg.NewServiceSecure("example.com", 443, true)
			rawReq := []byte("GET /fed-endpoint HTTP/1.1\r\nHost: example.com\r\n\r\n")
			req := httpmsg.NewHttpRequestWithService(service, rawReq)
			rawResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>fed</html>")
			rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse(rawResp))
			feeder.Feed(rr)
		}
	}
	return nil, nil
}
func (m *feedbackPassiveModule) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

type contextualPassiveModule struct {
	id        string
	cancelled atomic.Bool
}

func (m *contextualPassiveModule) ID() string                                     { return m.id }
func (m *contextualPassiveModule) Name() string                                   { return m.id }
func (m *contextualPassiveModule) Description() string                            { return "" }
func (m *contextualPassiveModule) ShortDescription() string                       { return "" }
func (m *contextualPassiveModule) ConfirmationCriteria() string                   { return "" }
func (m *contextualPassiveModule) Severity() severity.Severity                    { return 0 }
func (m *contextualPassiveModule) Confidence() severity.Confidence                { return 0 }
func (m *contextualPassiveModule) ScanScopes() modules.ScanScope                  { return modkit.ScanScopeRequest }
func (m *contextualPassiveModule) Tags() []string                                 { return nil }
func (m *contextualPassiveModule) CanProcess(_ *httpmsg.HttpRequestResponse) bool { return true }
func (m *contextualPassiveModule) Scope() modules.PassiveScanScope {
	return modkit.PassiveScanScopeBoth
}
func (m *contextualPassiveModule) ScanPerRequest(_ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m *contextualPassiveModule) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m *contextualPassiveModule) ScanPerRequestContext(ctx context.Context, _ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	<-ctx.Done()
	m.cancelled.Store(true)
	return nil, ctx.Err()
}
func (m *contextualPassiveModule) ScanPerHostContext(_ context.Context, _ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// sliceSource is a simple InputSource backed by a slice.
type sliceSource struct {
	items []*work.WorkItem
	idx   int
}

func (s *sliceSource) Next(_ context.Context) (*work.WorkItem, error) {
	if s.idx >= len(s.items) {
		return nil, io.EOF
	}
	item := s.items[s.idx]
	s.idx++
	return item, nil
}

func (s *sliceSource) Close() error { return nil }

// fakeActiveModule is a minimal modules.Module for unit-testing
// runActiveWithTimeout. It deliberately does NOT implement modules.TimeoutHinter.
type fakeActiveModule struct {
	id string
}

func (m *fakeActiveModule) ID() string                                     { return m.id }
func (m *fakeActiveModule) Name() string                                   { return m.id }
func (m *fakeActiveModule) Description() string                            { return "" }
func (m *fakeActiveModule) ShortDescription() string                       { return "" }
func (m *fakeActiveModule) ConfirmationCriteria() string                   { return "" }
func (m *fakeActiveModule) Severity() severity.Severity                    { return 0 }
func (m *fakeActiveModule) Confidence() severity.Confidence                { return 0 }
func (m *fakeActiveModule) ScanScopes() modules.ScanScope                  { return modkit.ScanScopeRequest }
func (m *fakeActiveModule) Tags() []string                                 { return nil }
func (m *fakeActiveModule) CanProcess(_ *httpmsg.HttpRequestResponse) bool { return true }

// fakeActiveHinterModule additionally implements modules.TimeoutHinter.
type fakeActiveHinterModule struct {
	fakeActiveModule
	hint time.Duration
}

func (m *fakeActiveHinterModule) TimeoutHint() time.Duration { return m.hint }

func TestRunActiveWithTimeout_FastCompletes(t *testing.T) {
	e := &Executor{cfg: ExecutorConfig{ActiveModuleTimeout: 200 * time.Millisecond}}
	_, item := makeTestItem("example.com", "/", "ok")
	want := []*output.ResultEvent{{}}

	got, completed := e.runActiveWithTimeout(context.Background(),
		func() ([]*output.ResultEvent, error) { return want, nil },
		&fakeActiveModule{id: "fast"}, item)

	if !completed {
		t.Fatal("expected completed=true for a fast module")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
}

func TestRunActiveWithTimeout_SlowTimesOut(t *testing.T) {
	e := &Executor{cfg: ExecutorConfig{ActiveModuleTimeout: 20 * time.Millisecond}}
	_, item := makeTestItem("example.com", "/", "ok")

	start := time.Now()
	got, completed := e.runActiveWithTimeout(context.Background(),
		func() ([]*output.ResultEvent, error) {
			time.Sleep(2 * time.Second)
			return []*output.ResultEvent{{}}, nil
		},
		&fakeActiveModule{id: "slow"}, item)

	if completed {
		t.Fatal("expected completed=false when the module exceeds its timeout")
	}
	if got != nil {
		t.Fatalf("expected nil results on timeout, got %d", len(got))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected prompt timeout return, took %s", elapsed)
	}
}

func TestRunActiveWithTimeout_TimeoutHinterRaisesBound(t *testing.T) {
	// Default would cut at 20ms; the module's hint raises it to 1s, so an
	// 80ms scan completes instead of being killed.
	e := &Executor{cfg: ExecutorConfig{ActiveModuleTimeout: 20 * time.Millisecond}}
	_, item := makeTestItem("example.com", "/", "ok")
	want := []*output.ResultEvent{{}}

	got, completed := e.runActiveWithTimeout(context.Background(),
		func() ([]*output.ResultEvent, error) {
			time.Sleep(80 * time.Millisecond)
			return want, nil
		},
		&fakeActiveHinterModule{fakeActiveModule{id: "hinted"}, time.Second}, item)

	if !completed {
		t.Fatal("expected completed=true: TimeoutHint should raise the bound above the default")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
}

func TestRunActiveWithTimeout_ModuleErrorMarksCompleted(t *testing.T) {
	e := &Executor{cfg: ExecutorConfig{ActiveModuleTimeout: 200 * time.Millisecond}}
	_, item := makeTestItem("example.com", "/", "ok")

	got, completed := e.runActiveWithTimeout(context.Background(),
		func() ([]*output.ResultEvent, error) { return nil, fmt.Errorf("boom") },
		&fakeActiveModule{id: "errs"}, item)

	// A module that returns an error still "completed" (it ran to conclusion);
	// the caller skips processResults because there are no results.
	if !completed {
		t.Fatal("expected completed=true when the module returns an error")
	}
	if got != nil {
		t.Fatalf("expected nil results on error, got %d", len(got))
	}
}

func TestRunActiveWithTimeout_CanceledCtxReturnsPromptly(t *testing.T) {
	// Simulates the phase deadline (max_duration) firing: the derived callCtx
	// is already done, so the guard returns immediately even though the module
	// would otherwise block, unblocking the worker's g.Wait().
	e := &Executor{cfg: ExecutorConfig{ActiveModuleTimeout: 10 * time.Second}}
	_, item := makeTestItem("example.com", "/", "ok")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	got, completed := e.runActiveWithTimeout(ctx,
		func() ([]*output.ResultEvent, error) {
			time.Sleep(2 * time.Second) // leaked goroutine drains into the buffered chan
			return []*output.ResultEvent{{}}, nil
		},
		&fakeActiveModule{id: "blocked"}, item)

	if completed {
		t.Fatal("expected completed=false when the phase context is canceled")
	}
	if got != nil {
		t.Fatalf("expected nil results on cancellation, got %d", len(got))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected prompt return on canceled ctx, took %s", elapsed)
	}
}
