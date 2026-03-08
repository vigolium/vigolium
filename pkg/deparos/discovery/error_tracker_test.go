package discovery

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// mockNetError implements net.Error for testing
type mockNetError struct {
	timeout   bool
	temporary bool
}

func (e *mockNetError) Error() string   { return "mock network error" }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

var _ net.Error = (*mockNetError)(nil)

func TestNewNetworkErrorTracker(t *testing.T) {
	t.Run("threshold=0 returns nil", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(0, func() {})
		if tracker != nil {
			t.Error("expected nil tracker for threshold=0")
		}
	})

	t.Run("negative threshold returns nil", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(-5, func() {})
		if tracker != nil {
			t.Error("expected nil tracker for negative threshold")
		}
	})

	t.Run("positive threshold creates tracker", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(10, func() {})
		if tracker == nil {
			t.Fatal("expected non-nil tracker")
		}
		if tracker.Threshold() != 10 {
			t.Errorf("expected threshold 10, got %d", tracker.Threshold())
		}
	})
}

func TestNetworkErrorTracker_RecordError(t *testing.T) {
	t.Run("nil tracker is safe", func(t *testing.T) {
		var tracker *NetworkErrorTracker
		result := tracker.RecordError(&mockNetError{})
		if result {
			t.Error("nil tracker should return false")
		}
	})

	t.Run("non-network error is ignored", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(3, func() {})
		result := tracker.RecordError(errors.New("regular error"))
		if result {
			t.Error("non-network error should return false")
		}
		if tracker.ConsecutiveErrors() != 0 {
			t.Errorf("expected 0 errors, got %d", tracker.ConsecutiveErrors())
		}
	})

	t.Run("network error increments counter", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(10, func() {})
		tracker.RecordError(&mockNetError{})
		if tracker.ConsecutiveErrors() != 1 {
			t.Errorf("expected 1 error, got %d", tracker.ConsecutiveErrors())
		}
		tracker.RecordError(&mockNetError{})
		if tracker.ConsecutiveErrors() != 2 {
			t.Errorf("expected 2 errors, got %d", tracker.ConsecutiveErrors())
		}
	})

	t.Run("threshold triggers cancel", func(t *testing.T) {
		var cancelled atomic.Bool
		tracker := NewNetworkErrorTracker(3, func() { cancelled.Store(true) })

		tracker.RecordError(&mockNetError{})
		tracker.RecordError(&mockNetError{})
		if cancelled.Load() {
			t.Error("should not cancel before threshold")
		}

		result := tracker.RecordError(&mockNetError{})
		if !result {
			t.Error("should return true when threshold reached")
		}
		if !cancelled.Load() {
			t.Error("should cancel when threshold reached")
		}
	})

	t.Run("cancel only called once", func(t *testing.T) {
		var cancelCount atomic.Int32
		tracker := NewNetworkErrorTracker(2, func() { cancelCount.Add(1) })

		tracker.RecordError(&mockNetError{})
		tracker.RecordError(&mockNetError{}) // triggers
		tracker.RecordError(&mockNetError{}) // should not trigger again
		tracker.RecordError(&mockNetError{}) // should not trigger again

		if cancelCount.Load() != 1 {
			t.Errorf("expected cancel called once, got %d", cancelCount.Load())
		}
	})
}

func TestNetworkErrorTracker_RecordSuccess(t *testing.T) {
	t.Run("nil tracker is safe", func(t *testing.T) {
		var tracker *NetworkErrorTracker
		tracker.RecordSuccess() // should not panic
	})

	t.Run("resets counter after errors", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(10, func() {})
		tracker.RecordError(&mockNetError{})
		tracker.RecordError(&mockNetError{})
		if tracker.ConsecutiveErrors() != 2 {
			t.Errorf("expected 2 errors, got %d", tracker.ConsecutiveErrors())
		}

		tracker.RecordSuccess()
		if tracker.ConsecutiveErrors() != 0 {
			t.Errorf("expected 0 errors after success, got %d", tracker.ConsecutiveErrors())
		}
	})

	t.Run("multiple successes are idempotent", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(10, func() {})
		tracker.RecordSuccess()
		tracker.RecordSuccess()
		if tracker.ConsecutiveErrors() != 0 {
			t.Errorf("expected 0 errors, got %d", tracker.ConsecutiveErrors())
		}
	})
}

func TestNetworkErrorTracker_ConcurrentAccess(t *testing.T) {
	var cancelled atomic.Bool
	tracker := NewNetworkErrorTracker(100, func() { cancelled.Store(true) })

	var wg sync.WaitGroup
	numWorkers := 50
	errorsPerWorker := 10

	// Half workers record errors, half record success
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < errorsPerWorker; j++ {
				if workerID%2 == 0 {
					tracker.RecordError(&mockNetError{})
				} else {
					tracker.RecordSuccess()
				}
			}
		}(i)
	}

	wg.Wait()

	// Counter should be some value >= 0 (exact value depends on interleaving)
	count := tracker.ConsecutiveErrors()
	if count < 0 {
		t.Errorf("counter should not be negative, got %d", count)
	}
}

func TestNetworkErrorTracker_ThresholdBehavior(t *testing.T) {
	t.Run("warning at 50 consecutive errors", func(t *testing.T) {
		// Warning should be logged at exactly 50 errors
		tracker := NewNetworkErrorTracker(100, func() {})

		for i := 0; i < 50; i++ {
			tracker.RecordError(&mockNetError{})
		}

		// warningLogged should be true after 50 errors
		if !tracker.warningLogged.Load() {
			t.Error("expected warning to be logged at 50 errors")
		}
	})

	t.Run("no warning before 50 errors", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(100, func() {})

		for i := 0; i < 49; i++ {
			tracker.RecordError(&mockNetError{})
		}

		if tracker.warningLogged.Load() {
			t.Error("warning should not be logged before 50 errors")
		}
	})

	t.Run("warning resets after success", func(t *testing.T) {
		tracker := NewNetworkErrorTracker(100, func() {})

		// Hit 50 errors
		for i := 0; i < 50; i++ {
			tracker.RecordError(&mockNetError{})
		}
		if !tracker.warningLogged.Load() {
			t.Error("expected warning logged")
		}

		// Reset
		tracker.RecordSuccess()
		if tracker.warningLogged.Load() {
			t.Error("warning flag should reset after success")
		}
	})
}

func TestNetworkErrorTracker_RealContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tracker := NewNetworkErrorTracker(3, cancel)

	// Verify context is not cancelled yet
	select {
	case <-ctx.Done():
		t.Fatal("context should not be cancelled yet")
	default:
	}

	// Hit threshold
	tracker.RecordError(&mockNetError{})
	tracker.RecordError(&mockNetError{})
	tracker.RecordError(&mockNetError{})

	// Verify context is now cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("context should be cancelled after threshold reached")
	}
}
