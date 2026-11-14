package http

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
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
	if string(cached.Body()) != "test body" {
		t.Errorf("expected body 'test body', got %q", string(cached.Body()))
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

// TestCachedResponse_DecodedBodyNotReDecoded guards against a regression where a
// gzipped response cached by the clusterer was decoded twice. responsechain.Fill
// decompresses the body per Content-Encoding, but the response keeps that header;
// if the cached entry retains it, reconstructing and re-filling hands the already
// plaintext body to gzip.NewReader, whose internal bufio pulls a 4096-byte chunk
// off the body before the header parse fails — silently dropping the first ~4096
// bytes of the stored response. snapshotResponse must strip the now-stale
// content-coding / framing headers so the cached entry is self-consistent and the
// body round-trips byte-for-byte through reconstruction.
func TestCachedResponse_DecodedBodyNotReDecoded(t *testing.T) {
	// A body larger than bufio's 4096 default so a dropped first chunk is visible.
	payload := make([]byte, 100000)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}

	var gzbuf bytes.Buffer
	gz := gzip.NewWriter(&gzbuf)
	if _, err := gz.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	// A response as the transport delivers it when the scanner sends its own
	// Accept-Encoding: a compressed body with the Content-Encoding header retained.
	// responsechain.Fill decodes it; snapshotResponse then captures the decoded body.
	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Encoding": {"gzip"},
			"Content-Type":     {"application/javascript"},
			"Content-Length":   {fmt.Sprint(gzbuf.Len())},
		},
		Body: io.NopCloser(bytes.NewReader(gzbuf.Bytes())),
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

	cached := snapshotResponse(chain, 0)
	chain.Close()

	if string(cached.Body()) != string(payload) {
		t.Fatalf("snapshot body mismatch: got %d bytes, want %d", len(cached.Body()), len(payload))
	}
	// The cached entry must not advertise an encoding or framing that no longer
	// matches its decoded body.
	for _, h := range []string{"Content-Encoding", "Content-Length", "Transfer-Encoding"} {
		if v := cached.Header.Get(h); v != "" {
			t.Errorf("cached header still carries %s=%q over a decoded body", h, v)
		}
	}

	rebuilt := cached.ToResponseChain()
	defer rebuilt.Close()
	if got := rebuilt.BodyBytes(); string(got) != string(payload) {
		t.Fatalf("reconstructed body corrupted: got %d bytes, want %d (dropped %d)",
			len(got), len(payload), len(payload)-len(got))
	}
	if v := rebuilt.Response().Header.Get("Content-Encoding"); v != "" {
		t.Errorf("reconstructed response still advertises Content-Encoding %q", v)
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

	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
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

	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
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

// TestRequestClusterer_LargeBodyNotCached verifies the byte-budget guard: a
// response larger than the per-entry cap is served (and still singleflight-deduped
// in flight) but never retained in the post-request cache, so a stream of unique
// large responses can't pin gigabytes. A repeated request therefore re-hits the
// origin instead of returning a cached copy.
func TestRequestClusterer_LargeBodyNotCached(t *testing.T) {
	big := strings.Repeat("A", clusterCacheMaxEntryBytes+1024) // just over the per-entry cap
	var serverHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		w.WriteHeader(200)
		_, _ = io.WriteString(w, big)
	}))
	defer ts.Close()

	rc := NewRequestClusterer()
	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
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
		return chain, 5, nil
	}

	rr := makeTestRR(t, ts.URL)

	c1, _, err := rc.Execute(rr, Options{}, mockExecute)
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()

	// Second call within TTL: because the big body was not cached, this must
	// re-execute against the origin rather than return a cache hit.
	c2, dur2, err := rc.Execute(rr, Options{}, mockExecute)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()

	if serverHits.Load() != 2 {
		t.Errorf("server hits = %d, want 2 (large body must not be cached)", serverHits.Load())
	}
	stats := rc.Stats()
	if dur2 == 0 {
		t.Error("second call reported a cache hit (duration 0) for an uncacheable large body")
	}
	if stats.SizeRejects < 1 {
		t.Errorf("SizeRejects = %d, want >= 1", stats.SizeRejects)
	}
	if stats.RetainedBytes != 0 {
		t.Errorf("RetainedBytes = %d, want 0 (nothing cacheable was retained)", stats.RetainedBytes)
	}
}

// TestRequestClusterer_RetainedBytesTracked confirms a normal (sub-cap) response
// is counted against the byte budget when cached.
func TestRequestClusterer_RetainedBytesTracked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "small-cacheable-body")
	}))
	defer ts.Close()

	rc := NewRequestClusterer()
	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
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
	c, _, err := rc.Execute(rr, Options{}, mockExecute)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	if got := rc.Stats().RetainedBytes; got <= 0 {
		t.Errorf("RetainedBytes = %d, want > 0 after caching a small body", got)
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

	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
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

	mockExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
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

	directExecute := func(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
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

// NewRequestClusterer creates a RequestClusterer with the default LRU size.
func NewRequestClusterer() *RequestClusterer {
	return NewRequestClustererWithSize(clusterCacheSize)
}
