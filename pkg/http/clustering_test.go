package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	httpUtils "github.com/projectdiscovery/utils/http"
)

func makeTestRR(t *testing.T, url string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(url)
	if err != nil {
		t.Fatalf("failed to create test request: %v", err)
	}
	return rr
}

func TestComputeClusterKey_SameRequest(t *testing.T) {
	rr1 := makeTestRR(t, "http://example.com/path")
	rr2 := makeTestRR(t, "http://example.com/path")

	opts := Options{}
	key1 := computeClusterKey(rr1, opts)
	key2 := computeClusterKey(rr2, opts)

	if key1 != key2 {
		t.Errorf("same request should produce same key: %s != %s", key1, key2)
	}
}

func TestComputeClusterKey_DifferentURL(t *testing.T) {
	rr1 := makeTestRR(t, "http://example.com/a")
	rr2 := makeTestRR(t, "http://example.com/b")

	opts := Options{}
	key1 := computeClusterKey(rr1, opts)
	key2 := computeClusterKey(rr2, opts)

	if key1 == key2 {
		t.Error("different URLs should produce different keys")
	}
}

func TestComputeClusterKey_DifferentOpts(t *testing.T) {
	rr := makeTestRR(t, "http://example.com/path")

	key1 := computeClusterKey(rr, Options{})
	key2 := computeClusterKey(rr, Options{NoRedirects: true})
	key3 := computeClusterKey(rr, Options{RawRequest: true})

	if key1 == key2 {
		t.Error("NoRedirects should change key")
	}
	if key1 == key3 {
		t.Error("RawRequest should change key")
	}
	if key2 == key3 {
		t.Error("different option combos should produce different keys")
	}
}

func TestCachedResponse_Roundtrip(t *testing.T) {
	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "hello")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "test body")
	}))
	defer ts.Close()

	// Make a real request to get a ResponseChain
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
	for chain.Has() {
		if err := chain.Fill(); err != nil {
			t.Fatal(err)
		}
		if !chain.Previous() {
			break
		}
	}

	// Snapshot
	cached := snapshotResponse(chain, 42)
	chain.Close()

	// Verify snapshot
	if cached.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", cached.StatusCode)
	}
	if cached.Duration != 42 {
		t.Errorf("expected duration 42, got %d", cached.Duration)
	}
	if string(cached.Body) != "test body" {
		t.Errorf("expected body 'test body', got %q", string(cached.Body))
	}

	// Reconstruct
	rebuilt := cached.ToResponseChain()
	defer rebuilt.Close()

	if rebuilt.Response().StatusCode != 200 {
		t.Errorf("rebuilt status: expected 200, got %d", rebuilt.Response().StatusCode)
	}
	if rebuilt.BodyString() != "test body" {
		t.Errorf("rebuilt body: expected 'test body', got %q", rebuilt.BodyString())
	}
	if rebuilt.Response().Header.Get("X-Test") != "hello" {
		t.Errorf("rebuilt header: expected 'hello', got %q", rebuilt.Response().Header.Get("X-Test"))
	}
}

func TestRequestClusterer_Singleflight(t *testing.T) {
	var serverHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		time.Sleep(50 * time.Millisecond) // Slow enough that all goroutines are in-flight
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "clustered response")
	}))
	defer ts.Close()

	rc := NewRequestClusterer()

	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
		resp, err := http.Get(ts.URL)
		if err != nil {
			return nil, 0, err
		}
		chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
		for chain.Has() {
			if err := chain.Fill(); err != nil {
				return nil, 0, err
			}
			if !chain.Previous() {
				break
			}
		}
		return chain, 1, nil
	}

	rr := makeTestRR(t, ts.URL)
	n := 10

	var wg sync.WaitGroup
	results := make([]*httpUtils.ResponseChain, n)
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			chain, _, err := rc.Execute(rr, Options{}, mockExecute)
			results[idx] = chain
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	// All should succeed
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d error: %v", i, err)
		}
	}

	// All should have valid response bodies
	for i, chain := range results {
		if chain == nil {
			t.Errorf("goroutine %d: nil chain", i)
			continue
		}
		if chain.BodyString() != "clustered response" {
			t.Errorf("goroutine %d: expected 'clustered response', got %q", i, chain.BodyString())
		}
		chain.Close()
	}

	// Server should have been hit only once
	hits := serverHits.Load()
	if hits != 1 {
		t.Errorf("expected 1 server hit (singleflight), got %d", hits)
	}

	stats := rc.Stats()
	if stats.Total != int64(n) {
		t.Errorf("expected total=%d, got %d", n, stats.Total)
	}
	// singleflight reports shared=true for ALL callers (including the one that ran the func)
	// when the result was shared. So clustered + cache_hits >= n-1.
	saved := stats.Clustered + stats.CacheHits
	if saved < int64(n-1) {
		t.Errorf("expected at least %d clustered+cache_hits, got %d (clustered=%d, cache_hits=%d)",
			n-1, saved, stats.Clustered, stats.CacheHits)
	}
}

func TestRequestClusterer_CacheHit(t *testing.T) {
	var serverHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "cached")
	}))
	defer ts.Close()

	rc := NewRequestClusterer()

	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
		resp, err := http.Get(ts.URL)
		if err != nil {
			return nil, 0, err
		}
		chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
		for chain.Has() {
			if err := chain.Fill(); err != nil {
				return nil, 0, err
			}
			if !chain.Previous() {
				break
			}
		}
		return chain, 2, nil
	}

	rr := makeTestRR(t, ts.URL)

	// First call
	chain1, dur1, err := rc.Execute(rr, Options{}, mockExecute)
	if err != nil {
		t.Fatal(err)
	}
	chain1.Close()

	if dur1 != 2 {
		t.Errorf("first call duration: expected 2, got %d", dur1)
	}

	// Second call (within TTL) — should be cache hit
	chain2, dur2, err := rc.Execute(rr, Options{}, mockExecute)
	if err != nil {
		t.Fatal(err)
	}
	defer chain2.Close()

	if dur2 != 0 {
		t.Errorf("cache hit duration: expected 0, got %d", dur2)
	}
	if chain2.BodyString() != "cached" {
		t.Errorf("cache hit body: expected 'cached', got %q", chain2.BodyString())
	}

	if serverHits.Load() != 1 {
		t.Errorf("expected 1 server hit, got %d", serverHits.Load())
	}

	stats := rc.Stats()
	if stats.CacheHits != 1 {
		t.Errorf("expected 1 cache hit, got %d", stats.CacheHits)
	}
}

func TestRequestClusterer_CacheExpiry(t *testing.T) {
	var serverHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "fresh")
	}))
	defer ts.Close()

	rc := NewRequestClusterer()

	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
		resp, err := http.Get(ts.URL)
		if err != nil {
			return nil, 0, err
		}
		chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
		for chain.Has() {
			if err := chain.Fill(); err != nil {
				return nil, 0, err
			}
			if !chain.Previous() {
				break
			}
		}
		return chain, 1, nil
	}

	rr := makeTestRR(t, ts.URL)

	// First call
	chain1, _, err := rc.Execute(rr, Options{}, mockExecute)
	if err != nil {
		t.Fatal(err)
	}
	chain1.Close()

	// Wait for TTL to expire
	time.Sleep(clusterCacheTTL + 50*time.Millisecond)

	// Second call — should miss cache
	chain2, _, err := rc.Execute(rr, Options{}, mockExecute)
	if err != nil {
		t.Fatal(err)
	}
	chain2.Close()

	if serverHits.Load() != 2 {
		t.Errorf("expected 2 server hits after TTL expiry, got %d", serverHits.Load())
	}
}

func TestRequestClusterer_ErrorPropagation(t *testing.T) {
	rc := NewRequestClusterer()

	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
		time.Sleep(50 * time.Millisecond)
		return nil, 0, fmt.Errorf("connection refused")
	}

	rr := makeTestRR(t, "http://unreachable.invalid/path")
	n := 5

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _, err := rc.Execute(rr, Options{}, mockExecute)
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err == nil {
			t.Errorf("goroutine %d: expected error, got nil", i)
		}
	}
}

func TestRequestClusterer_NoClustering(t *testing.T) {
	var serverHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "direct")
	}))
	defer ts.Close()

	rc := NewRequestClusterer()

	directExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
		resp, err := http.Get(ts.URL)
		if err != nil {
			return nil, 0, err
		}
		chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
		for chain.Has() {
			if err := chain.Fill(); err != nil {
				return nil, 0, err
			}
			if !chain.Previous() {
				break
			}
		}
		return chain, 1, nil
	}

	rr := makeTestRR(t, ts.URL)

	// First call (populates cache)
	chain1, _, err := rc.Execute(rr, Options{}, directExecute)
	if err != nil {
		t.Fatal(err)
	}
	chain1.Close()

	// The NoClustering opt-out is handled at the Requester.Execute level,
	// not inside the clusterer itself. This test verifies the clusterer
	// does cache on normal calls.
	if rc.Stats().Total != 1 {
		t.Errorf("expected total=1, got %d", rc.Stats().Total)
	}
}
