package core

import (
	goruntime "runtime"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// --- shardmap.go -------------------------------------------------------------

func TestShardedMap_StoreLoadUpdate(t *testing.T) {
	sm := newShardedMap(4)

	if _, ok := sm.Load("missing"); ok {
		t.Error("Load on empty map should report not-found")
	}

	sm.Store("k", "v1")
	if v, ok := sm.Load("k"); !ok || v != "v1" {
		t.Errorf("Load(k) = (%q,%v), want (v1,true)", v, ok)
	}

	// updating an existing key replaces the value without growing order ring
	sm.Store("k", "v2")
	if v, ok := sm.Load("k"); !ok || v != "v2" {
		t.Errorf("Load(k) after update = (%q,%v), want (v2,true)", v, ok)
	}
}

func TestShardedMap_PowerOfTwoAndManyKeys(t *testing.T) {
	// shardHint=10 rounds up to 16 shards; mask must be 15.
	sm := newShardedMap(10)
	if sm.mask != 15 {
		t.Errorf("mask = %d, want 15 (16 shards)", sm.mask)
	}
	// Store many keys across shards and read them all back.
	for i := 0; i < 1000; i++ {
		k := keyN(i)
		sm.Store(k, k)
	}
	for i := 0; i < 1000; i++ {
		k := keyN(i)
		if v, ok := sm.Load(k); !ok || v != k {
			t.Fatalf("Load(%q) = (%q,%v), want (%q,true)", k, v, ok, k)
		}
	}
}

func TestShardedMap_Eviction(t *testing.T) {
	// maxEntries=64 across 16 shards floors at 64 per shard. Fill one shard
	// well past capacity and confirm the map stays bounded (FIFO eviction)
	// without panicking and still serves recent keys.
	sm := newShardedMap(1, 64)
	const n = 5000
	for i := 0; i < n; i++ {
		k := keyN(i)
		sm.Store(k, k)
	}
	// The most recently stored key should still be present.
	last := keyN(n - 1)
	if v, ok := sm.Load(last); !ok || v != last {
		t.Errorf("most recent key %q not found after eviction churn", last)
	}
}

func keyN(i int) string {
	// small helper to avoid importing strconv just for this
	const digits = "0123456789"
	if i == 0 {
		return "k0"
	}
	buf := []byte{}
	for i > 0 {
		buf = append([]byte{digits[i%10]}, buf...)
		i /= 10
	}
	return "k" + string(buf)
}

// --- response buffer pool ----------------------------------------------------

func TestResponseBufferPool_Tiers(t *testing.T) {
	sizes := []int{
		1024,               // small
		poolTierSmall + 1,  // medium
		poolTierMedium + 1, // large
	}
	for _, n := range sizes {
		b := getResponseBuffer(n)
		if len(b) != n {
			t.Errorf("getResponseBuffer(%d) len = %d, want %d", n, len(b), n)
		}
		putResponseBuffer(b)
	}

	// Oversized: bypasses pools, returns a fresh slice of exact length.
	huge := poolTierLarge + 1
	b := getResponseBuffer(huge)
	if len(b) != huge {
		t.Errorf("oversized getResponseBuffer len = %d, want %d", len(b), huge)
	}
	// putting an oversized buffer back is a no-op (must not panic).
	putResponseBuffer(b)
}

func TestResponseBufferPool_Reuse(t *testing.T) {
	// Put a small buffer, then a Get for a small size should hand back a
	// buffer with enough capacity (not panic, correct length).
	putResponseBuffer(make([]byte, 0, 4096))
	b := getResponseBuffer(2048)
	if len(b) != 2048 {
		t.Errorf("reused buffer len = %d, want 2048", len(b))
	}
}

// --- executor config helpers -------------------------------------------------

func TestDefaultExecutorConfig(t *testing.T) {
	cfg := DefaultExecutorConfig()
	if cfg.Workers != goruntime.NumCPU() {
		t.Errorf("Workers = %d, want NumCPU=%d", cfg.Workers, goruntime.NumCPU())
	}
}

func TestSuggestWorkerCount(t *testing.T) {
	tests := []struct {
		name        string
		moduleCount int
		maxWorkers  int
		want        int
	}{
		{"floor at 2", 0, 100, 2},
		{"scales 2x modules", 5, 100, 10},
		{"capped at maxWorkers", 50, 16, 16},
		{"single module floored", 0, 1, 1}, // suggested 2 but cap 1
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SuggestWorkerCount(tt.moduleCount, tt.maxWorkers); got != tt.want {
				t.Errorf("SuggestWorkerCount(%d,%d) = %d, want %d", tt.moduleCount, tt.maxWorkers, got, tt.want)
			}
		})
	}
}

// --- NewExecutor + stats getters ---------------------------------------------

func TestNewExecutor_QuiescentGetters(t *testing.T) {
	e := NewExecutor(DefaultExecutorConfig(), &sliceSource{}, nil, nil)

	if got := e.Processed(); got != 0 {
		t.Errorf("Processed() = %d, want 0", got)
	}
	if m := e.ModuleMetrics(); m == nil {
		t.Error("ModuleMetrics() should return a non-nil snapshot")
	} else if len(m) != 0 {
		t.Errorf("ModuleMetrics() len = %d, want 0 before any scan", len(m))
	}
	if got := e.FeedbackDropped(); got != 0 {
		t.Errorf("FeedbackDropped() = %d, want 0", got)
	}
	if got := e.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d, want 0", got)
	}
	if got := e.ConsideredModuleCount(); got != 0 {
		t.Errorf("ConsideredModuleCount() = %d, want 0", got)
	}

	// Workers <= 0 in config is normalized up to NumCPU.
	e2 := NewExecutor(ExecutorConfig{Workers: 0}, &sliceSource{}, nil, nil)
	if e2.cfg.Workers != goruntime.NumCPU() {
		t.Errorf("NewExecutor normalized Workers = %d, want NumCPU", e2.cfg.Workers)
	}

	// DisableFeedback leaves feeder nil; FeedbackDropped guards against that.
	e3 := NewExecutor(ExecutorConfig{Workers: 1, DisableFeedback: true}, &sliceSource{}, nil, nil)
	if got := e3.FeedbackDropped(); got != 0 {
		t.Errorf("FeedbackDropped() with DisableFeedback = %d, want 0", got)
	}
}

// --- executor_adapters.go ----------------------------------------------------

func TestExecutorFeeder_FeedAndDrop(t *testing.T) {
	f := &executorFeeder{ch: make(chan *work.WorkItem, 1)}
	rr := &httpmsg.HttpRequestResponse{}

	if !f.Feed(rr) {
		t.Error("first Feed into empty channel should succeed")
	}
	// channel now full (cap 1) -> next Feed is dropped
	if f.Feed(rr) {
		t.Error("Feed into full channel should be dropped (return false)")
	}
	if got := f.Dropped(); got != 1 {
		t.Errorf("Dropped() = %d, want 1", got)
	}
}

func TestNopFeeder(t *testing.T) {
	if nopFeederInstance.Feed(nil) {
		t.Error("nopFeeder.Feed should always return false")
	}
}

func TestExecutorIPProvider_GetInsertionPoints(t *testing.T) {
	raw := []byte("GET /search?q=1&page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// nil cache: computes directly each call.
	nilProvider := &executorIPProvider{cache: nil}
	pts, err := nilProvider.GetInsertionPoints(raw, "req-1", true)
	if err != nil {
		t.Fatalf("GetInsertionPoints (nil cache) error = %v", err)
	}
	if len(pts) == 0 {
		t.Error("expected insertion points from query params")
	}

	// with cache: first call is a miss (computes + stores), second is a hit.
	cache, _ := lru.New[string, []httpmsg.InsertionPoint](16)
	cached := &executorIPProvider{cache: cache}
	if _, err := cached.GetInsertionPoints(raw, "req-2", true); err != nil {
		t.Fatalf("GetInsertionPoints (cache miss) error = %v", err)
	}
	if cache.Len() == 0 {
		t.Error("expected cache to be populated after miss")
	}
	hit, err := cached.GetInsertionPoints(raw, "req-2", true)
	if err != nil {
		t.Fatalf("GetInsertionPoints (cache hit) error = %v", err)
	}
	if len(hit) != len(pts) {
		t.Errorf("cache hit returned %d points, want %d", len(hit), len(pts))
	}

	// shallow variant uses a distinct cache key.
	if _, err := cached.GetInsertionPoints(raw, "req-2", false); err != nil {
		t.Fatalf("GetInsertionPoints (shallow) error = %v", err)
	}
	if cache.Len() < 2 {
		t.Errorf("shallow variant should add a distinct key; cache len = %d", cache.Len())
	}
}
