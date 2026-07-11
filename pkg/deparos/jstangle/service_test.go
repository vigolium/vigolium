package jstangle

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeServiceBackend struct {
	calls atomic.Int64
	scan  func(context.Context, []byte, ScanOptions) (*ScanResult, error)
}

func (b *fakeServiceBackend) ScanWithOptions(ctx context.Context, content []byte, options ScanOptions) (*ScanResult, error) {
	b.calls.Add(1)
	if b.scan != nil {
		return b.scan(ctx, content, options)
	}
	result := &ScanResult{
		Requests: []ExtractedRequest{{URL: "/api/original", Method: "GET"}},
		Code:     &CodeRecord{Filename: "asset.js", Content: "generated"},
		Analysis: &AnalysisResultV2{SchemaVersion: 2},
	}
	result.Analysis.Source.URL = options.SourceURL
	return result, nil
}

func (b *fakeServiceBackend) Capabilities() (*Capabilities, error) {
	return &Capabilities{Type: "capabilities", ProtocolVersion: ProtocolVersion, SourceHash: "test-source-hash"}, nil
}

func testService(backend serviceBackend, maxWeight, cacheBytes int64) *Service {
	return newServiceWithBackend(&ServiceConfig{MaxWeight: maxWeight, CacheBytes: cacheBytes}, backend)
}

func TestServiceCachesByContentAndRebindsSource(t *testing.T) {
	backend := &fakeServiceBackend{}
	service := testService(backend, 4, 1024*1024)
	defer func() { _ = service.Close() }()

	content := []byte(`fetch('/api/original')`)
	first, err := service.ScanWithOptions(context.Background(), content, ScanOptions{
		Profile: ProfileDiscovery, SourceURL: "https://one.example/assets/app.js",
	})
	if err != nil {
		t.Fatalf("first analysis: %v", err)
	}
	first.Requests[0].URL = "/consumer-mutated"
	first.Code.Content = "consumer-mutated"

	second, err := service.ScanWithOptions(context.Background(), content, ScanOptions{
		Profile: ProfileDiscovery, SourceURL: "https://two.example/static/app.js",
	})
	if err != nil {
		t.Fatalf("cached analysis: %v", err)
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("backend calls = %d, want 1", got)
	}
	if second.Analysis == nil || second.Analysis.Source.URL != "https://two.example/static/app.js" {
		t.Fatalf("source URL was not rebound: %#v", second.Analysis)
	}
	if second.Requests[0].URL != "/api/original" || second.Code == nil || second.Code.Content != "generated" {
		t.Fatalf("cached result was mutated by another consumer: %#v", second)
	}
	stats := service.Stats()
	if stats.CacheHits != 1 || stats.JobsStarted != 1 || stats.PayloadEntries != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if profile := stats.Profiles[string(ProfileDiscovery)]; profile.Jobs != 1 || profile.Complete != 1 {
		t.Fatalf("profile metrics counted cache hits or lost the worker job: %+v", stats.Profiles)
	}
}

func TestServiceCoalescesInflightAndIsolatesCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	backend := &fakeServiceBackend{scan: func(ctx context.Context, _ []byte, _ ScanOptions) (*ScanResult, error) {
		close(started)
		select {
		case <-release:
			return &ScanResult{Requests: []ExtractedRequest{{URL: "/api/shared", Method: "GET"}}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	service := testService(backend, 4, 0)
	defer func() { _ = service.Close() }()

	ctx1, cancel1 := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := service.ScanWithOptions(ctx1, []byte("same-content"), ScanOptions{Profile: ProfileEndpoints})
		firstErr <- err
	}()
	<-started

	secondResult := make(chan *ScanResult, 1)
	secondErr := make(chan error, 1)
	go func() {
		result, err := service.ScanWithOptions(context.Background(), []byte("same-content"), ScanOptions{Profile: ProfileEndpoints})
		secondResult <- result
		secondErr <- err
	}()

	deadline := time.Now().Add(time.Second)
	for service.Stats().Coalesced == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel1()
	if err := <-firstErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("first caller error = %v, want context.Canceled", err)
	}
	close(release)
	if err := <-secondErr; err != nil {
		t.Fatalf("second caller failed after first cancelled: %v", err)
	}
	if result := <-secondResult; result == nil || len(result.Requests) != 1 {
		t.Fatalf("second caller received incomplete result: %#v", result)
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("backend calls = %d, want 1", got)
	}
}

func TestServiceCancelsBackendWhenLastWaiterLeaves(t *testing.T) {
	started := make(chan struct{})
	backendCancelled := make(chan struct{})
	backend := &fakeServiceBackend{scan: func(ctx context.Context, _ []byte, _ ScanOptions) (*ScanResult, error) {
		close(started)
		<-ctx.Done()
		close(backendCancelled)
		return nil, ctx.Err()
	}}
	service := testService(backend, 2, 0)
	defer func() { _ = service.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := service.ScanWithOptions(ctx, []byte("cancel-me"), ScanOptions{Profile: ProfileEndpoints})
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller error = %v, want context.Canceled", err)
	}
	select {
	case <-backendCancelled:
	case <-time.After(time.Second):
		t.Fatal("backend context was not cancelled after the last waiter left")
	}
}

func TestServiceWeightedAdmissionSerializesHeavyJobs(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{}, 2)
	var active atomic.Int64
	var maxActive atomic.Int64
	backend := &fakeServiceBackend{scan: func(ctx context.Context, content []byte, _ ScanOptions) (*ScanResult, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maxActive.Load()
			if current <= observed || maxActive.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- string(content)
		select {
		case <-release:
			return &ScanResult{Requests: []ExtractedRequest{}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	service := testService(backend, 2, 0)
	defer func() { _ = service.Close() }()

	var wg sync.WaitGroup
	for _, content := range []string{"first", "second"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = service.ScanWithOptions(context.Background(), []byte(content), ScanOptions{Profile: ProfileEndpoints})
		}()
	}

	<-started
	select {
	case second := <-started:
		t.Fatalf("second heavy job started before admission released: %s", second)
	case <-time.After(75 * time.Millisecond):
	}
	release <- struct{}{}
	<-started
	release <- struct{}{}
	wg.Wait()
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent backend jobs = %d, want 1", got)
	}
}

func TestByteLRUEvictsLeastRecentlyUsedByBytes(t *testing.T) {
	cache := newByteLRU[string](6)
	cache.add("a", "A", 3)
	cache.add("b", "B", 3)
	if _, ok := cache.get("a"); !ok {
		t.Fatal("expected a in cache")
	}
	cache.add("c", "C", 3)
	if _, ok := cache.get("b"); ok {
		t.Fatal("least-recently-used entry b was not evicted")
	}
	if _, ok := cache.get("a"); !ok {
		t.Fatal("recent entry a was evicted")
	}
}

func TestServiceLargeDiscoveryUsesLiteProfile(t *testing.T) {
	var observedProfile AnalysisProfile
	backend := &fakeServiceBackend{scan: func(_ context.Context, _ []byte, options ScanOptions) (*ScanResult, error) {
		observedProfile = options.Profile
		return &ScanResult{Code: &CodeRecord{Content: "must-be-dropped"}, Analysis: &AnalysisResultV2{}}, nil
	}}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 16, MaxASTInputBytes: 128, HardInputBytes: 256,
	}, backend)
	defer func() { _ = service.Close() }()
	result, err := service.ScanWithOptions(context.Background(), []byte("fetch('/api/users') plus padding"), ScanOptions{Profile: ProfileDiscovery})
	if err != nil {
		t.Fatal(err)
	}
	if observedProfile != ProfileDiscoveryLite {
		t.Fatalf("backend profile = %q, want discovery-lite", observedProfile)
	}
	if result.Code != nil || result.Analysis == nil || result.Analysis.Stats.Status != "partial" {
		t.Fatalf("large-input degradation was not explicit: %#v", result)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "large_input_profile_degraded" {
		t.Fatalf("missing degradation diagnostic: %#v", result.Diagnostics)
	}
	if stats := service.Stats(); stats.DegradedJobs != 1 || stats.FallbackJobs != 0 {
		t.Fatalf("unexpected degradation metrics: %+v", stats)
	}
}

func TestServiceVeryLargeUsesBoundedFallbackWithoutBackend(t *testing.T) {
	backend := &fakeServiceBackend{}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 16, MaxASTInputBytes: 64, HardInputBytes: 512,
	}, backend)
	defer func() { _ = service.Close() }()
	content := []byte("fetch('/api/users'); import('./lazy.js'); //# sourceMappingURL=app.js.map\n" + string(make([]byte, 80)))
	result, err := service.ScanWithOptions(context.Background(), content, ScanOptions{Profile: ProfileDiscovery, SourceURL: "https://example.test/assets/app.js"})
	if err != nil {
		t.Fatal(err)
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("AST backend was called %d time(s)", backend.calls.Load())
	}
	if result.Analysis == nil || result.Analysis.Stats.Status != "partial" || result.Completion == nil || result.Completion.Status != "partial" {
		t.Fatalf("fallback did not report partial output: %#v", result)
	}
	if len(result.RequestFacts) != 1 || result.RequestFacts[0].Provenance.Confidence != "low" {
		t.Fatalf("fallback endpoint hint missing or replayable: %#v", result.RequestFacts)
	}
	if len(result.AssetFacts) < 2 {
		t.Fatalf("fallback asset extraction incomplete: %#v", result.AssetFacts)
	}
	if stats := service.Stats(); stats.FallbackJobs != 1 || stats.JobsCompleted != 1 {
		t.Fatalf("unexpected fallback metrics: %+v", stats)
	}
}

func TestServiceParserFailureDegradesToBoundedFallback(t *testing.T) {
	backend := &fakeServiceBackend{scan: func(_ context.Context, _ []byte, options ScanOptions) (*ScanResult, error) {
		result := &ScanResult{Analysis: &AnalysisResultV2{}}
		result.Analysis.Stats.Status = "failed"
		result.Completion = &ScanCompletion{Status: "failed", ReasonCode: "ast_node_limit_reached", Profile: options.Profile}
		result.Diagnostics = []Diagnostic{{Type: "diagnostic", Severity: "error", Stage: "parse", Code: "ast_node_limit_reached"}}
		return result, nil
	}}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 1024, MaxASTInputBytes: 2048, HardInputBytes: 4096,
	}, backend)
	defer func() { _ = service.Close() }()
	result, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/api/fallback')`), ScanOptions{Profile: ProfileEndpoints})
	if err != nil {
		t.Fatal(err)
	}
	if result.Completion == nil || result.Completion.Status != "partial" || result.Completion.ReasonCode != "ast_node_limit_reached_fallback" {
		t.Fatalf("failed AST result did not become an explicit partial fallback: %#v", result.Completion)
	}
	if len(result.RequestFacts) != 1 || result.RequestFacts[0].Provenance.Confidence != "low" {
		t.Fatalf("fallback did not retain a bounded hint: %#v", result.RequestFacts)
	}
	if stats := service.Stats(); stats.FallbackJobs != 1 || stats.DegradedJobs != 1 {
		t.Fatalf("unexpected parser fallback stats: %+v", stats)
	}
}

func TestServiceWorkerFailureDegradesDiscoveryButNotDOM(t *testing.T) {
	backend := &fakeServiceBackend{scan: func(context.Context, []byte, ScanOptions) (*ScanResult, error) {
		return nil, errors.New("worker crashed")
	}}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 1024, MaxASTInputBytes: 2048, HardInputBytes: 4096,
	}, backend)
	defer func() { _ = service.Close() }()
	result, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/api/recovered')`), ScanOptions{Profile: ProfileDiscovery})
	if err != nil || result == nil || result.Completion == nil || result.Completion.ReasonCode != "worker_failure_fallback" {
		t.Fatalf("discovery worker failure did not degrade safely: result=%#v err=%v", result, err)
	}
	if _, err := service.ScanWithOptions(context.Background(), []byte(`location.hash`), ScanOptions{Profile: ProfileDOMSecurity}); err == nil {
		t.Fatal("DOM-only worker failure was incorrectly presented as endpoint fallback")
	}
}

func TestServiceHardInputLimitRejectsBeforeBackend(t *testing.T) {
	backend := &fakeServiceBackend{}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 1, HardInputBytes: 16, MaxASTInputBytes: 8, NormalInputBytes: 4,
	}, backend)
	defer func() { _ = service.Close() }()
	_, err := service.ScanWithOptions(context.Background(), make([]byte, 17), ScanOptions{Profile: ProfileEndpoints})
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("error = %v, want ErrInputTooLarge", err)
	}
	if backend.calls.Load() != 0 || service.Stats().RejectedJobs != 1 {
		t.Fatalf("hard rejection reached backend or lost metrics: calls=%d stats=%+v", backend.calls.Load(), service.Stats())
	}
}
