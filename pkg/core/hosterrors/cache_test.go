package hosterrors

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheCheck(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, nil)

	for i := range 100 {
		cache.MarkFailed("example.com:443:GET", fmt.Errorf("could not resolve host"), true)
		got := cache.Check("example.com:443:GET")
		if i < 2 {
			// till 3 the host is not flagged to skip
			require.False(t, got)
		} else {
			// above 3 it must remain flagged to skip
			require.True(t, got)
		}
	}

	value := cache.Check("example.com:443:GET")
	require.Equal(t, true, value, "could not get checked value")
}

func TestTrackErrors(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, []string{"custom error"})

	for i := range 100 {
		cache.MarkFailed("custom.com:80:POST", fmt.Errorf("got: nested: custom error"), true)
		got := cache.Check("custom.com:80:POST")
		if i < 2 {
			// till 3 the host is not flagged to skip
			require.False(t, got)
		} else {
			// above 3 it must remain flagged to skip
			require.True(t, got)
		}
	}
	value := cache.Check("custom.com:80:POST")
	require.Equal(t, true, value, "could not get checked value")
}

func TestCacheItemDo(t *testing.T) {
	var (
		count int
		item  cacheItem
	)

	wg := sync.WaitGroup{}
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			item.Do(func() {
				count++
			})
		}()
	}
	wg.Wait()

	// ensures the increment happened only once regardless of the multiple call
	require.Equal(t, count, 1)
}

func TestCacheMarkFailed(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, nil)

	// All use host:port:method format now (matching HttpRequestResponse.ID())
	tests := []struct {
		host     string
		expected int
	}{
		{"example.com:80:GET", 1},
		{"example.com:80:GET", 2},  // Same host+method, error count increases
		{"example.com:80:POST", 1}, // Same host, different method, new entry
		{"other.com:443:GET", 1},   // Different host, new entry
	}

	for _, test := range tests {
		cache.MarkFailed(test.host, fmt.Errorf("no address found for host"), true)
		failedTarget, err := cache.failedTargets.Get(test.host)
		require.Nil(t, err)
		require.NotNil(t, failedTarget)

		value, ok := failedTarget.(*cacheItem)
		require.True(t, ok)
		require.EqualValues(t, test.expected, value.errors.Load())
	}
}

func TestCacheMarkFailedConcurrent(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, nil)

	tests := []struct {
		host     string
		expected int32
	}{
		{"example.com:80:GET", 100},
		{"example.com:443:POST", 100},
		{"other.com:8080:GET", 100},
	}

	// the cache is not atomic during items creation, so we pre-create them with counter to zero
	for _, test := range tests {
		newItem := &cacheItem{errors: atomic.Int32{}}
		newItem.errors.Store(0)
		_ = cache.failedTargets.Set(test.host, newItem)
	}

	wg := sync.WaitGroup{}
	for _, test := range tests {
		currentTest := test
		for range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cache.MarkFailed(currentTest.host, fmt.Errorf("could not resolve host"), true)
			}()
		}
	}
	wg.Wait()

	for _, test := range tests {
		require.True(t, cache.Check(test.host))

		failedTarget, err := cache.failedTargets.Get(test.host)
		require.Nil(t, err)
		require.NotNil(t, failedTarget)

		value, ok := failedTarget.(*cacheItem)
		require.True(t, ok)
		require.EqualValues(t, test.expected, value.errors.Load())
	}
}

func TestCacheMarkSuccess(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, nil)

	// Mark failed twice with host:port:method format
	cache.MarkFailed("example.com:80:GET", fmt.Errorf("could not resolve host"), true)
	cache.MarkFailed("example.com:80:GET", fmt.Errorf("could not resolve host"), true)

	// Verify error count is 2
	item, err := cache.failedTargets.Get("example.com:80:GET")
	require.Nil(t, err)
	require.EqualValues(t, 2, item.(*cacheItem).errors.Load())

	// Mark success - should reset counter
	cache.MarkSuccess("example.com:80:GET")

	// Verify error count is reset to 0
	item, err = cache.failedTargets.Get("example.com:80:GET")
	require.Nil(t, err)
	require.EqualValues(t, 0, item.(*cacheItem).errors.Load())

	// Verify host is not quarantined
	require.False(t, cache.Check("example.com:80:GET"))
}

func TestCacheMarkSuccessDoesNotResetQuarantined(t *testing.T) {
	cache := New(3, DefaultMaxHostsCount, nil)

	// Mark failed 3 times to quarantine
	cache.MarkFailed("example.com:443:GET", fmt.Errorf("could not resolve host"), true)
	cache.MarkFailed("example.com:443:GET", fmt.Errorf("could not resolve host"), true)
	cache.MarkFailed("example.com:443:GET", fmt.Errorf("could not resolve host"), true)

	// Verify host is quarantined
	require.True(t, cache.Check("example.com:443:GET"))

	// Mark success - should NOT reset counter (already quarantined)
	cache.MarkSuccess("example.com:443:GET")

	// Verify error count is still 3
	item, err := cache.failedTargets.Get("example.com:443:GET")
	require.Nil(t, err)
	require.EqualValues(t, 3, item.(*cacheItem).errors.Load())

	// Verify host is still quarantined
	require.True(t, cache.Check("example.com:443:GET"))
}
