package waf

import (
	"context"
	"sync/atomic"

	"go.uber.org/zap"
)

// Package-level logger for WAF tracking.
var logger = zap.NewNop()

// SetLogger configures the package-level logger.
func SetLogger(l *zap.Logger) {
	if l != nil {
		logger = l
	}
}

// BlockTracker tracks consecutive WAF/CDN block responses across all workers.
// When the threshold is reached, it cancels the discovery context to trigger
// graceful shutdown. This helps detect when a WAF is actively blocking traffic.
//
// Thread-safe for concurrent access from multiple workers.
type BlockTracker struct {
	threshold     int32
	consecutive   atomic.Int32
	cancel        context.CancelFunc
	warningLogged atomic.Bool
	exitTriggered atomic.Bool

	// Statistics
	totalBlocks   atomic.Uint64
	lastBlockInfo atomic.Pointer[BlockInfo]
}

// NewBlockTracker creates a tracker with the given threshold.
// If threshold is 0 or negative, tracking is disabled (returns nil).
// The cancel function is called when the threshold is reached.
func NewBlockTracker(threshold int, cancel context.CancelFunc) *BlockTracker {
	if threshold <= 0 {
		return nil
	}
	return &BlockTracker{
		threshold: int32(threshold),
		cancel:    cancel,
	}
}

// RecordBlock increments the consecutive block counter.
// Returns true if the threshold was reached and discovery is being stopped.
func (t *BlockTracker) RecordBlock(info *BlockInfo) bool {
	if t == nil || t.threshold <= 0 {
		return false
	}

	// Store block info and increment total
	if info != nil {
		t.lastBlockInfo.Store(info)
	}
	t.totalBlocks.Add(1)

	count := t.consecutive.Add(1)

	// Log warning after 10 consecutive blocks (only once per block streak)
	const warningAt int32 = 10
	if count == warningAt && t.warningLogged.CompareAndSwap(false, true) {
		wafType := "unknown"
		if info != nil {
			wafType = info.WAFType
		}
		logger.Warn("High consecutive WAF blocks detected",
			zap.Int32("current", count),
			zap.Int32("threshold", t.threshold),
			zap.String("waf_type", wafType))
	}

	// Check if threshold reached
	if count >= t.threshold {
		if t.exitTriggered.CompareAndSwap(false, true) {
			wafType := "unknown"
			url := ""
			if info != nil {
				wafType = info.WAFType
				url = info.URL
			}
			logger.Error("Consecutive WAF block threshold reached, stopping discovery",
				zap.Int32("blocks", count),
				zap.Int32("threshold", t.threshold),
				zap.String("waf_type", wafType),
				zap.String("last_url", url))
			t.cancel()
		}
		return true
	}

	return false
}

// RecordSuccess resets the consecutive block counter.
// Called when a non-blocked response is received.
func (t *BlockTracker) RecordSuccess() {
	if t == nil || t.threshold <= 0 {
		return
	}

	old := t.consecutive.Swap(0)
	if old > 0 {
		logger.Debug("Consecutive WAF block counter reset after successful response",
			zap.Int32("was", old))
		t.warningLogged.Store(false) // Reset warning flag for next streak
	}
}

// ConsecutiveBlocks returns the current consecutive block count.
func (t *BlockTracker) ConsecutiveBlocks() int32 {
	if t == nil {
		return 0
	}
	return t.consecutive.Load()
}

// TotalBlocks returns the total number of WAF blocks detected.
func (t *BlockTracker) TotalBlocks() uint64 {
	if t == nil {
		return 0
	}
	return t.totalBlocks.Load()
}

// LastBlockInfo returns information about the most recent block.
func (t *BlockTracker) LastBlockInfo() *BlockInfo {
	if t == nil {
		return nil
	}
	return t.lastBlockInfo.Load()
}

// Threshold returns the configured threshold.
func (t *BlockTracker) Threshold() int32 {
	if t == nil {
		return 0
	}
	return t.threshold
}
