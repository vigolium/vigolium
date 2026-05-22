package dedup

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDiskSet builds a DiskSet rooted in a per-test temp dir so cleanup is
// automatic via t.TempDir(). Cleanup:false leaves removal to the test harness.
func newTestDiskSet(t *testing.T) *DiskSet {
	t.Helper()
	ds, err := NewDiskSet(DiskSetOptions{Path: t.TempDir(), Cleanup: false})
	require.NoError(t, err)
	require.NotNil(t, ds)
	t.Cleanup(func() { _ = ds.Close() })
	return ds
}

// TestDiskSet_IsSeen_FirstSeenThenRepeat is the central dedup behavior: a key
// is "not seen" the first time (and gets recorded) and "seen" every time after.
func TestDiskSet_IsSeen_FirstSeenThenRepeat(t *testing.T) {
	ds := newTestDiskSet(t)

	assert.False(t, ds.IsSeen("alpha"), "first sighting must report not-seen")
	assert.True(t, ds.IsSeen("alpha"), "repeat sighting must report seen")
	assert.True(t, ds.IsSeen("alpha"), "still seen on third sighting")

	// A distinct key is independent.
	assert.False(t, ds.IsSeen("beta"), "a different key is its own first sighting")
}

// TestDiskSet_SizeAndHits verifies the running counters: Size counts unique
// first-sightings, Hits counts duplicate sightings.
func TestDiskSet_SizeAndHits(t *testing.T) {
	ds := newTestDiskSet(t)

	assert.Equal(t, int64(0), ds.Size())
	assert.Equal(t, uint64(0), ds.Hits())

	ds.IsSeen("a") // unique  -> size 1
	ds.IsSeen("b") // unique  -> size 2
	ds.IsSeen("a") // dup     -> hit 1
	ds.IsSeen("a") // dup     -> hit 2
	ds.IsSeen("c") // unique  -> size 3

	assert.Equal(t, int64(3), ds.Size(), "three distinct keys recorded")
	assert.Equal(t, uint64(2), ds.Hits(), "two duplicate sightings counted")
}

// TestDiskSet_Contains is a read-only membership check that must NOT record the
// key — i.e. probing a key with Contains leaves a later IsSeen reporting
// not-seen.
func TestDiskSet_Contains(t *testing.T) {
	ds := newTestDiskSet(t)

	assert.False(t, ds.Contains("ghost"), "absent key is not contained")
	assert.False(t, ds.IsSeen("ghost"), "Contains must not have recorded the key")

	// IsSeen now recorded it, so Contains sees it.
	assert.True(t, ds.Contains("ghost"), "key present after IsSeen records it")
}

// TestDiskSet_IncrementAndCheck verifies the counter fires at the configured
// limit: shouldContinue stays true while count <= limit and flips false once it
// exceeds.
func TestDiskSet_IncrementAndCheck(t *testing.T) {
	ds := newTestDiskSet(t)
	const limit = 3

	tests := []struct {
		wantCount    int
		wantContinue bool
	}{
		{1, true},
		{2, true},
		{3, true},  // exactly at limit still continues
		{4, false}, // exceeds limit -> stop
		{5, false},
	}
	for i, tc := range tests {
		count, cont := ds.IncrementAndCheck("counter-key", limit)
		assert.Equalf(t, tc.wantCount, count, "call %d count", i)
		assert.Equalf(t, tc.wantContinue, cont, "call %d shouldContinue", i)
	}

	// A different key keeps its own independent count.
	count, cont := ds.IncrementAndCheck("other-key", limit)
	assert.Equal(t, 1, count)
	assert.True(t, cont)
}

// TestDiskSet_Close_BehavesAfterClose documents post-Close behavior: IsSeen
// returns true (already-seen, to halt processing) and Contains returns false.
func TestDiskSet_Close_BehavesAfterClose(t *testing.T) {
	ds, err := NewDiskSet(DiskSetOptions{Path: t.TempDir(), Cleanup: false})
	require.NoError(t, err)

	ds.IsSeen("x")
	require.NoError(t, ds.Close())

	assert.True(t, ds.IsSeen("x"), "closed set treats everything as seen")
	assert.False(t, ds.Contains("x"), "closed set Contains returns false")
	count, cont := ds.IncrementAndCheck("x", 10)
	assert.Equal(t, 0, count)
	assert.False(t, cont, "closed set must not allow continuation")

	// Close is idempotent.
	assert.NoError(t, ds.Close())
}

// TestDiskSet_Cleanup_RemovesPath verifies Cleanup:true wipes the on-disk store
// on Close, while Cleanup:false leaves it.
func TestDiskSet_Cleanup_RemovesPath(t *testing.T) {
	path := t.TempDir() + "/cleanup-store"
	ds, err := NewDiskSet(DiskSetOptions{Path: path, Cleanup: true})
	require.NoError(t, err)
	ds.IsSeen("k")
	require.DirExists(t, path)

	require.NoError(t, ds.Close())
	assert.NoDirExists(t, path, "Cleanup:true must remove the store directory")
}

// TestDiskSet_DefaultPath_UsesTempDir confirms an empty Path provisions a temp
// directory under the system temp dir and cleans up on Close.
func TestDiskSet_DefaultPath_UsesTempDir(t *testing.T) {
	ds, err := NewDiskSet(DiskSetOptions{Cleanup: true}) // empty Path
	require.NoError(t, err)
	require.NotEmpty(t, ds.path)
	require.DirExists(t, ds.path)

	created := ds.path
	require.NoError(t, ds.Close())
	assert.NoDirExists(t, created)
}

// TestDiskSet_IsSeen_Concurrent stresses the atomic check-then-put: many
// goroutines racing on the same key must yield exactly one "not seen" and the
// rest "seen", with Size==1 and Hits==(n-1). Run under -race for the data-race
// guarantee.
func TestDiskSet_IsSeen_Concurrent(t *testing.T) {
	ds := newTestDiskSet(t)

	const n = 200
	var notSeen atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !ds.IsSeen("race-key") {
				notSeen.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), notSeen.Load(), "exactly one goroutine sees the key first")
	assert.Equal(t, int64(1), ds.Size(), "only one unique key recorded")
	assert.Equal(t, uint64(n-1), ds.Hits(), "every other sighting is a duplicate")
}

// TestDiskSet_IncrementAndCheck_Concurrent ensures concurrent increments never
// lose updates (final count equals the number of calls) and that exactly one
// goroutine observes each count value.
func TestDiskSet_IncrementAndCheck_Concurrent(t *testing.T) {
	ds := newTestDiskSet(t)

	const n = 150
	var wg sync.WaitGroup
	seen := make([]atomic.Bool, n+1)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			count, _ := ds.IncrementAndCheck("k", n*2) // limit high enough not to matter
			if count >= 1 && count <= n {
				seen[count].Store(true)
			}
		}()
	}
	wg.Wait()

	// Final increment must equal exactly n (no lost updates).
	final, _ := ds.IncrementAndCheck("k", n*2)
	assert.Equal(t, n+1, final, "no increments lost under concurrency")

	for c := 1; c <= n; c++ {
		assert.Truef(t, seen[c].Load(), "count value %d should have been observed exactly once", c)
	}
}

// TestDiskSet_PersistsAcrossReopen verifies the store is durable: keys recorded
// before Close are still present when the same path is reopened.
func TestDiskSet_PersistsAcrossReopen(t *testing.T) {
	path := t.TempDir() + "/persist-store"

	ds1, err := NewDiskSet(DiskSetOptions{Path: path, Cleanup: false})
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		ds1.IsSeen(fmt.Sprintf("key-%d", i))
	}
	require.NoError(t, ds1.Close())

	ds2, err := NewDiskSet(DiskSetOptions{Path: path, Cleanup: true})
	require.NoError(t, err)
	defer func() { _ = ds2.Close() }()

	for i := 0; i < 5; i++ {
		assert.Truef(t, ds2.Contains(fmt.Sprintf("key-%d", i)), "key-%d must survive reopen", i)
	}
	assert.False(t, ds2.Contains("never-written"))
}
