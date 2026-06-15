package ratelimit

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
)

// AIMD tuning for adaptive per-host concurrency. These are deliberately gentle:
// the limiter only diverges from the static MaxPerHost when a host shows distress,
// and recovers slowly so a single error doesn't whipsaw the limit.
const (
	// decreaseCooldown collapses a burst of distress signals into one back-off, so
	// N concurrent failures halve the limit once, not N times.
	decreaseCooldown = 1 * time.Second
	// increaseAfterHealthy is the run of healthy completions that earns a +1
	// ramp toward the ceiling. Scaling it by the current limit keeps the ramp rate
	// roughly proportional (a +1 step is cheaper to earn when the limit is small).
	increaseAfterHealthy = 4
)

// newEntry builds a hostEntry for the limiter's current mode. Static mode gets a
// fixed-cap channel semaphore (the unchanged hot path); adaptive mode gets a
// resizable token pool sized to the ramp ceiling and pre-filled to the start
// limit (MaxPerHost).
func (h *HostRateLimiter) newEntry() *hostEntry {
	if !h.adaptive {
		return &hostEntry{sem: make(chan struct{}, h.maxPerHost)}
	}
	start := min(max(h.maxPerHost, h.minPerHost), h.ceilingPerHost)
	e := &hostEntry{tokens: make(chan struct{}, h.ceilingPerHost)}
	e.limit.Store(int64(start))
	for i := 0; i < start; i++ {
		e.tokens <- struct{}{}
	}
	return e
}

// Feedback reports the outcome of one request to the host so adaptive mode can
// adjust its concurrency limit. It is a no-op in static mode (and for an evicted
// host). A distress signal (429/503/502/504, connection error, or timeout) backs
// the limit off; a healthy completion counts toward the next ramp-up. statusCode
// may be 0 when err != nil (transport-level failure).
func (h *HostRateLimiter) Feedback(host string, statusCode int, err error) {
	if !h.adaptive {
		return
	}
	shard := h.shardFor(host)
	shard.mu.RLock()
	entry, ok := shard.hosts[host]
	shard.mu.RUnlock()
	if !ok || entry.tokens == nil {
		return
	}

	if isDistress(statusCode, err) {
		entry.healthy.Store(0)
		// One back-off per cooldown window — coalesce concurrent failures.
		now := time.Now().UnixNano()
		last := entry.lastDecr.Load()
		if now-last < int64(decreaseCooldown) {
			return
		}
		if !entry.lastDecr.CompareAndSwap(last, now) {
			return // another goroutine just backed off
		}
		cur := int(entry.limit.Load())
		target := max(cur/2, h.minPerHost)
		if target < cur {
			h.setLimit(entry, target)
			zap.L().Debug("HostRateLimiter: adaptive back-off",
				zap.String("host", host), zap.Int("from", cur), zap.Int("to", target),
				zap.Int("status", statusCode))
		}
		return
	}

	// Healthy: ramp +1 toward the ceiling once enough clean completions accrue.
	cur := int(entry.limit.Load())
	threshold := int64(increaseAfterHealthy + cur)
	if entry.healthy.Add(1) < threshold {
		return
	}
	entry.healthy.Store(0)
	if cur < h.ceilingPerHost {
		h.setLimit(entry, cur+1)
		zap.L().Debug("HostRateLimiter: adaptive ramp-up",
			zap.String("host", host), zap.Int("from", cur), zap.Int("to", cur+1))
	}
}

// setLimit resizes an adaptive entry's token pool to newLimit (clamped to
// [minPerHost, ceilingPerHost]), maintaining the invariant available+inflight ==
// limit. Growing pushes tokens into the pool; shrinking pulls available tokens
// non-blockingly and records the remainder as debt that Release retires. Held
// under the entry mutex so concurrent feedback events don't race the resize; the
// acquire/release hot paths never take this lock.
func (h *HostRateLimiter) setLimit(entry *hostEntry, newLimit int) {
	newLimit = min(max(newLimit, h.minPerHost), h.ceilingPerHost)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	old := int(entry.limit.Load())
	delta := newLimit - old
	if delta == 0 {
		return
	}
	entry.limit.Store(int64(newLimit))

	if delta > 0 {
		// Grow: make delta more tokens available. Non-blocking — the pool channel
		// is sized to the ceiling and total tokens never exceed newLimit <= cap.
		// First cancel any outstanding shrink debt, then add the rest.
		for delta > 0 {
			if d := entry.debt.Load(); d > 0 && entry.debt.CompareAndSwap(d, d-1) {
				delta--
				continue
			}
			select {
			case entry.tokens <- struct{}{}:
				delta--
			default:
				return // pool full; should not happen under the invariant
			}
		}
		return
	}

	// Shrink: remove -delta tokens. Pull available ones now; defer the rest to
	// Release via debt so we never block waiting for checked-out tokens.
	remove := -delta
	for remove > 0 {
		select {
		case <-entry.tokens:
			remove--
		default:
			entry.debt.Add(int64(remove))
			return
		}
	}
}

// isDistress classifies a request outcome as host distress worth backing off for:
// an explicit rate-limit/overload status, or a transport error (timeout, reset,
// refused). A nil error with a normal status is healthy.
func isDistress(statusCode int, err error) bool {
	if err != nil && !isContextCanceled(err) {
		return true
	}
	switch statusCode {
	case 429, 502, 503, 504:
		return true
	}
	return false
}

// isContextCanceled reports whether err is a context cancellation/deadline, which
// reflects scan shutdown rather than host distress and must not trigger back-off.
func isContextCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
