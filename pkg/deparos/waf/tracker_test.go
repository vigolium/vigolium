package waf

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBlockTracker(t *testing.T) {
	t.Run("returns nil for zero threshold", func(t *testing.T) {
		tracker := NewBlockTracker(0, func() {})
		assert.Nil(t, tracker)
	})

	t.Run("returns nil for negative threshold", func(t *testing.T) {
		tracker := NewBlockTracker(-5, func() {})
		assert.Nil(t, tracker)
	})

	t.Run("returns tracker for positive threshold", func(t *testing.T) {
		tracker := NewBlockTracker(10, func() {})
		require.NotNil(t, tracker)
		assert.Equal(t, int32(10), tracker.Threshold())
	})
}

func TestBlockTracker_NilSafety(t *testing.T) {
	var tracker *BlockTracker

	// All methods should be safe to call on nil tracker
	assert.False(t, tracker.RecordBlock(&BlockInfo{WAFType: "test"}))
	tracker.RecordSuccess()
	assert.Equal(t, int32(0), tracker.ConsecutiveBlocks())
	assert.Equal(t, uint64(0), tracker.TotalBlocks())
	assert.Nil(t, tracker.LastBlockInfo())
	assert.Equal(t, int32(0), tracker.Threshold())
}

func TestBlockTracker_RecordBlock(t *testing.T) {
	t.Run("increments consecutive counter", func(t *testing.T) {
		tracker := NewBlockTracker(100, func() {})
		require.NotNil(t, tracker)

		info := &BlockInfo{WAFType: "cloudflare", StatusCode: 403}

		tracker.RecordBlock(info)
		assert.Equal(t, int32(1), tracker.ConsecutiveBlocks())

		tracker.RecordBlock(info)
		assert.Equal(t, int32(2), tracker.ConsecutiveBlocks())

		tracker.RecordBlock(info)
		assert.Equal(t, int32(3), tracker.ConsecutiveBlocks())
	})

	t.Run("increments total blocks", func(t *testing.T) {
		tracker := NewBlockTracker(100, func() {})
		require.NotNil(t, tracker)

		info := &BlockInfo{WAFType: "akamai", StatusCode: 403}

		for i := 0; i < 5; i++ {
			tracker.RecordBlock(info)
		}
		assert.Equal(t, uint64(5), tracker.TotalBlocks())
	})

	t.Run("stores last block info", func(t *testing.T) {
		tracker := NewBlockTracker(100, func() {})
		require.NotNil(t, tracker)

		info1 := &BlockInfo{WAFType: "cloudflare", StatusCode: 403, URL: "http://example.com/a"}
		info2 := &BlockInfo{WAFType: "akamai", StatusCode: 429, URL: "http://example.com/b"}

		tracker.RecordBlock(info1)
		assert.Equal(t, "cloudflare", tracker.LastBlockInfo().WAFType)

		tracker.RecordBlock(info2)
		assert.Equal(t, "akamai", tracker.LastBlockInfo().WAFType)
		assert.Equal(t, "http://example.com/b", tracker.LastBlockInfo().URL)
	})

	t.Run("returns true when threshold reached", func(t *testing.T) {
		cancelled := false
		tracker := NewBlockTracker(3, func() { cancelled = true })
		require.NotNil(t, tracker)

		info := &BlockInfo{WAFType: "test"}

		assert.False(t, tracker.RecordBlock(info))
		assert.False(t, cancelled)

		assert.False(t, tracker.RecordBlock(info))
		assert.False(t, cancelled)

		assert.True(t, tracker.RecordBlock(info))
		assert.True(t, cancelled)
	})

	t.Run("calls cancel only once", func(t *testing.T) {
		cancelCount := 0
		tracker := NewBlockTracker(2, func() { cancelCount++ })
		require.NotNil(t, tracker)

		info := &BlockInfo{WAFType: "test"}

		tracker.RecordBlock(info)
		tracker.RecordBlock(info) // Reaches threshold
		tracker.RecordBlock(info) // Exceeds threshold
		tracker.RecordBlock(info)

		assert.Equal(t, 1, cancelCount)
	})
}

func TestBlockTracker_RecordSuccess(t *testing.T) {
	t.Run("resets consecutive counter", func(t *testing.T) {
		tracker := NewBlockTracker(100, func() {})
		require.NotNil(t, tracker)

		info := &BlockInfo{WAFType: "test"}

		tracker.RecordBlock(info)
		tracker.RecordBlock(info)
		tracker.RecordBlock(info)
		assert.Equal(t, int32(3), tracker.ConsecutiveBlocks())

		tracker.RecordSuccess()
		assert.Equal(t, int32(0), tracker.ConsecutiveBlocks())
	})

	t.Run("does not reset total blocks", func(t *testing.T) {
		tracker := NewBlockTracker(100, func() {})
		require.NotNil(t, tracker)

		info := &BlockInfo{WAFType: "test"}

		tracker.RecordBlock(info)
		tracker.RecordBlock(info)
		tracker.RecordBlock(info)
		tracker.RecordSuccess()

		assert.Equal(t, uint64(3), tracker.TotalBlocks())
	})
}

func TestBlockTracker_RealContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tracker := NewBlockTracker(3, cancel)
	require.NotNil(t, tracker)

	info := &BlockInfo{WAFType: "cloudflare", StatusCode: 403}

	// Simulate 3 consecutive blocks
	tracker.RecordBlock(info)
	tracker.RecordBlock(info)

	select {
	case <-ctx.Done():
		t.Fatal("context cancelled too early")
	default:
		// OK - context not yet cancelled
	}

	tracker.RecordBlock(info) // Should trigger cancellation

	select {
	case <-ctx.Done():
		// OK - context cancelled
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context not cancelled after threshold reached")
	}
}

func TestBlockTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewBlockTracker(1000, func() {})
	require.NotNil(t, tracker)

	var wg sync.WaitGroup
	goroutines := 100
	blocksPerGoroutine := 10

	// Concurrent blocks
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < blocksPerGoroutine; j++ {
				info := &BlockInfo{WAFType: "test", StatusCode: 403}
				tracker.RecordBlock(info)
			}
		}(i)
	}

	// Concurrent successes (to reset counter periodically)
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < blocksPerGoroutine; j++ {
				tracker.RecordSuccess()
			}
		}()
	}

	wg.Wait()

	// Total blocks should be exactly goroutines * blocksPerGoroutine
	assert.Equal(t, uint64(goroutines*blocksPerGoroutine), tracker.TotalBlocks())
}

func TestBlockTracker_ConcurrentThresholdRace(t *testing.T) {
	// Test that cancel is called exactly once even with concurrent access
	var cancelCount atomic.Int32
	tracker := NewBlockTracker(10, func() {
		cancelCount.Add(1)
	})
	require.NotNil(t, tracker)

	var wg sync.WaitGroup
	goroutines := 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := &BlockInfo{WAFType: "test"}
			for j := 0; j < 5; j++ {
				tracker.RecordBlock(info)
			}
		}()
	}

	wg.Wait()

	// Cancel should be called exactly once
	assert.Equal(t, int32(1), cancelCount.Load())
}
