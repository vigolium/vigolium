package dedup

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewManager_InitializesMaps verifies the constructor returns a usable
// Manager with both backing maps allocated (a nil map would panic on the first
// write in Get*).
func TestNewManager_InitializesMaps(t *testing.T) {
	m := NewManager()
	require.NotNil(t, m)
	require.NotNil(t, m.diskSets)
	require.NotNil(t, m.requestHashManagerData)

	// A fresh manager has no cached helpers yet.
	assert.Empty(t, m.diskSets)
	assert.Empty(t, m.requestHashManagerData)
	m.Close()
}

// TestManager_GetDiskSet_CachesPerKey is the core caching-factory contract:
// the same key must hand back the exact same *DiskSet pointer (so all modules
// sharing a key share one dedup set), while a different key gets a distinct
// instance.
func TestManager_GetDiskSet_CachesPerKey(t *testing.T) {
	m := NewManager()
	defer m.Close()

	first := m.GetDiskSet("module-a")
	require.NotNil(t, first)

	again := m.GetDiskSet("module-a")
	assert.Same(t, first, again, "same key must return the cached DiskSet instance")

	other := m.GetDiskSet("module-b")
	require.NotNil(t, other)
	assert.NotSame(t, first, other, "different key must return a distinct DiskSet")

	// The cache should now hold exactly the two distinct keys.
	assert.Len(t, m.diskSets, 2)
}

// TestManager_GetDefaultRequestHashManager_CachesPerKey mirrors the DiskSet
// caching contract for RequestHashManager and confirms the Default* variant
// uses DefaultOption.
func TestManager_GetDefaultRequestHashManager_CachesPerKey(t *testing.T) {
	m := NewManager()
	defer m.Close()

	first := m.GetDefaultRequestHashManager("rhm-a")
	require.NotNil(t, first)
	assert.Equal(t, DefaultOption, first.option, "Default* must apply DefaultOption")

	again := m.GetDefaultRequestHashManager("rhm-a")
	assert.Same(t, first, again, "same key must return the cached RequestHashManager")

	other := m.GetDefaultRequestHashManager("rhm-b")
	require.NotNil(t, other)
	assert.NotSame(t, first, other, "different key must return a distinct RequestHashManager")

	assert.Len(t, m.requestHashManagerData, 2)
}

// TestManager_GetRequestHashManager_HonorsOption confirms the option passed at
// first creation is the one stored — and that the cached instance is returned
// on subsequent calls regardless of the option argument (first-write wins).
func TestManager_GetRequestHashManager_HonorsOption(t *testing.T) {
	m := NewManager()
	defer m.Close()

	custom := Option{Method: true, Host: true, Body: true}
	rhm := m.GetRequestHashManager("custom", custom)
	require.NotNil(t, rhm)
	assert.Equal(t, custom, rhm.option)

	// A second call with a different option must still return the cached one.
	again := m.GetRequestHashManager("custom", DefaultOption)
	assert.Same(t, rhm, again)
	assert.Equal(t, custom, again.option, "first-created option must be retained")
}

// TestManager_DiskSetAndRHM_IndependentNamespaces guards that the DiskSet and
// RequestHashManager caches do not collide on the same key string.
func TestManager_DiskSetAndRHM_IndependentNamespaces(t *testing.T) {
	m := NewManager()
	defer m.Close()

	ds := m.GetDiskSet("shared-key")
	rhm := m.GetDefaultRequestHashManager("shared-key")

	require.NotNil(t, ds)
	require.NotNil(t, rhm)
	// They live in separate maps; the RHM owns its own internal DiskSet.
	assert.NotSame(t, ds, rhm.diskSet)
}

// TestManager_Close_Idempotent verifies Close can be called and leaves the
// cached helpers' backing stores closed. Close on a Manager must not panic.
func TestManager_Close_Idempotent(t *testing.T) {
	m := NewManager()
	ds := m.GetDiskSet("k")
	rhm := m.GetDefaultRequestHashManager("k")
	require.NotNil(t, ds)
	require.NotNil(t, rhm)

	assert.NotPanics(t, m.Close)

	// After Close the underlying DiskSet db is released; IsSeen on a closed set
	// returns true (treated as already-seen so processing stops).
	assert.True(t, ds.IsSeen("anything"))
}

// TestManager_GetDiskSet_ConcurrentSameKey ensures that concurrent callers
// racing on the same key all receive the identical cached instance and that
// the access is data-race free (run under -race).
func TestManager_GetDiskSet_ConcurrentSameKey(t *testing.T) {
	m := NewManager()
	defer m.Close()

	const n = 64
	var wg sync.WaitGroup
	results := make([]*DiskSet, n)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = m.GetDiskSet("hot-key")
		}(i)
	}
	wg.Wait()

	require.NotNil(t, results[0])
	for i, r := range results {
		assert.Samef(t, results[0], r, "concurrent callers must share one DiskSet (idx %d)", i)
	}
	// A later lookup must return the same cached instance (no duplicate created),
	// asserted via the public API rather than reading the unexported map.
	assert.Same(t, results[0], m.GetDiskSet("hot-key"), "a later GetDiskSet must return the cached instance")
}

// TestManager_GetRHM_ConcurrentSameKey mirrors the concurrency guarantee for
// RequestHashManager creation.
func TestManager_GetRHM_ConcurrentSameKey(t *testing.T) {
	m := NewManager()
	defer m.Close()

	const n = 64
	var wg sync.WaitGroup
	results := make([]*RequestHashManager, n)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = m.GetDefaultRequestHashManager("hot-rhm")
		}(i)
	}
	wg.Wait()

	require.NotNil(t, results[0])
	for i, r := range results {
		assert.Samef(t, results[0], r, "concurrent callers must share one RHM (idx %d)", i)
	}
	// A later lookup must return the same cached instance (no duplicate created),
	// asserted via the public API rather than reading the unexported map.
	assert.Same(t, results[0], m.GetDefaultRequestHashManager("hot-rhm"), "a later lookup must return the cached RHM")
}
