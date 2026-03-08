package discovery

import (
	"context"
	"sync/atomic"

	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"go.uber.org/zap"
)

// NetworkErrorTracker tracks consecutive network errors across all workers.
// When the threshold is reached, it cancels the discovery context to trigger
// graceful shutdown. This helps detect when a server is blocking our traffic.
//
// Thread-safe for concurrent access from multiple workers.
type NetworkErrorTracker struct {
	threshold     int32
	consecutive   atomic.Int32
	cancel        context.CancelFunc
	warningLogged atomic.Bool
	exitTriggered atomic.Bool
}

// NewNetworkErrorTracker creates a tracker with the given threshold.
// If threshold is 0 or negative, tracking is disabled (all methods are no-ops).
// The cancel function is called when the threshold is reached.
func NewNetworkErrorTracker(threshold int, cancel context.CancelFunc) *NetworkErrorTracker {
	if threshold <= 0 {
		return nil
	}
	return &NetworkErrorTracker{
		threshold: int32(threshold),
		cancel:    cancel,
	}
}

// RecordError increments the consecutive error counter if the error is a network error.
// Returns true if the threshold was reached and discovery is being stopped.
// Non-network errors (HTTP 4xx/5xx, analysis errors, etc.) are ignored.
func (t *NetworkErrorTracker) RecordError(err error) bool {
	if t == nil || t.threshold <= 0 {
		return false
	}

	// Only track retryable network errors (not HTTP status codes)
	if !pkghttp.IsRetryable(err) {
		return false
	}

	count := t.consecutive.Add(1)

	// Log warning after 50 consecutive errors (only once per error streak)
	const warningAt int32 = 50
	if count == warningAt && t.warningLogged.CompareAndSwap(false, true) {
		logger.Warn("High consecutive network errors detected",
			zap.Int32("current", count),
			zap.Int32("threshold", t.threshold),
			zap.Error(err))
	}

	// Check if threshold reached
	if count >= t.threshold {
		if t.exitTriggered.CompareAndSwap(false, true) {
			logger.Error("Consecutive network error threshold reached, stopping discovery",
				zap.Int32("errors", count),
				zap.Int32("threshold", t.threshold),
				zap.Error(err))
			t.cancel()
		}
		return true
	}

	return false
}

// RecordSuccess resets the consecutive error counter.
// Called when any HTTP response is received successfully (regardless of status code).
func (t *NetworkErrorTracker) RecordSuccess() {
	if t == nil || t.threshold <= 0 {
		return
	}

	old := t.consecutive.Swap(0)
	if old > 0 {
		logger.Debug("Consecutive error counter reset after successful response",
			zap.Int32("was", old))
		t.warningLogged.Store(false) // Reset warning flag for next time
	}
}

// ConsecutiveErrors returns the current consecutive error count.
func (t *NetworkErrorTracker) ConsecutiveErrors() int32 {
	if t == nil {
		return 0
	}
	return t.consecutive.Load()
}

// Threshold returns the configured threshold.
func (t *NetworkErrorTracker) Threshold() int32 {
	if t == nil {
		return 0
	}
	return t.threshold
}
