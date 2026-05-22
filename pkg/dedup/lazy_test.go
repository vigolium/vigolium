package dedup

import (
	"sync"
	"testing"
)

// TestLazy_ReresolvesPerManager guards the cross-scan pollution fix: scanner
// module instances are shared singletons, so a Lazy that cached the first
// Manager forever would hand later scans a previous (closed) scan's helper.
// Lazy must cache per Manager — reusing within one scan, re-resolving for a new
// one.
func TestLazy_ReresolvesPerManager(t *testing.T) {
	var calls int
	lazy := NewLazy(func(_ *Manager) *int {
		calls++
		v := calls
		return &v
	})

	m1 := NewManager()
	m2 := NewManager()

	v1 := lazy.Get(m1)
	if v1 == nil || *v1 != 1 {
		t.Fatalf("first Get should init once; got %v after %d calls", v1, calls)
	}
	if again := lazy.Get(m1); again != v1 {
		t.Error("same manager must return the cached value (no re-init)")
	}
	if calls != 1 {
		t.Errorf("same manager must not re-init: got %d calls", calls)
	}

	v2 := lazy.Get(m2)
	if v2 == nil || v2 == v1 {
		t.Error("a different manager must re-resolve to a fresh value")
	}
	if calls != 2 {
		t.Errorf("new manager must trigger one re-init: got %d calls", calls)
	}

	if lazy.Get(nil) != nil {
		t.Error("nil manager must return nil")
	}
}

// TestLazy_CachesNilPerManager guards against re-running initFunc on every call
// when the helper resolves to nil (e.g. a DiskSet/RHM that failed to create).
// The result must be cached once per Manager, matching the old sync.Once
// behavior, so a degraded scan doesn't re-attempt creation per request.
func TestLazy_CachesNilPerManager(t *testing.T) {
	var calls int
	lazy := NewLazy(func(_ *Manager) *int {
		calls++
		return nil // simulate a helper that fails to construct
	})
	m := NewManager()

	if lazy.Get(m) != nil {
		t.Fatal("nil-resolving initFunc must yield nil")
	}
	if lazy.Get(m) != nil {
		t.Fatal("still nil on repeat")
	}
	if calls != 1 {
		t.Errorf("nil result must be cached per Manager: got %d initFunc calls, want 1", calls)
	}

	// A different Manager still re-resolves (once).
	if lazy.Get(NewManager()) != nil {
		t.Fatal("nil-resolving initFunc must yield nil for a new manager too")
	}
	if calls != 2 {
		t.Errorf("new manager must re-resolve exactly once: got %d", calls)
	}
}

// TestLazy_ConcurrentGetSameManager ensures concurrent callers within a single
// scan (the executor fans modules across worker goroutines) init exactly once
// and never race.
func TestLazy_ConcurrentGetSameManager(t *testing.T) {
	var calls int
	lazy := NewLazy(func(_ *Manager) *int {
		calls++
		v := calls
		return &v
	})
	m := NewManager()

	var wg sync.WaitGroup
	results := make([]*int, 50)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = lazy.Get(m)
		}(i)
	}
	wg.Wait()

	if calls != 1 {
		t.Errorf("concurrent Get with one manager must init once: got %d", calls)
	}
	for i, r := range results {
		if r != results[0] {
			t.Fatalf("all concurrent callers must see the same value (idx %d differs)", i)
		}
	}
}
