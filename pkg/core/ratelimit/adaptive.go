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

// usesAdaptiveEntries reports whether hosts get resizable token pools rather than
// fixed semaphores — true under plain Adaptive mode and under WafAutoArm (where the
// pool sits pinned at MaxPerHost until a WAF block arms it).
func (h *HostRateLimiter) usesAdaptiveEntries() bool {
	return h.adaptive || h.wafAutoArm
}

// PreArmable reports whether PreArm can throttle a host — true only when hosts use
// adaptive token pools (plain Adaptive or WafAutoArm) AND proactive pacing has not
// been disabled (--no-waf-pacing). It lets a caller skip the per-response edge
// fingerprint entirely when pre-arming would be a no-op (static mode or disabled).
func (h *HostRateLimiter) PreArmable() bool {
	return h.usesAdaptiveEntries() && !h.preArmDisabled
}

// preArmStart is the reduced concurrency a host is dropped to when proactively
// pre-armed for a CDN/WAF edge (before any block). A firm quarter of MaxPerHost
// (floored at MinPerHost, never below 1): low enough that the active phase's opening
// burst does not arm a rate-based WAF, high enough that a healthy (non-WAF) edge
// ramps back toward the ceiling on clean completions. Deliberately more decisive
// than Feedback's reactive halving so the proactive drop meaningfully cuts the burst.
func (h *HostRateLimiter) preArmStart() int {
	// Floor at minPerHost (the constructor guarantees it is >= 1). Not redundant with
	// setLimit's own min-clamp: this value is also reported in PreArmNotice/logged, so
	// it must equal what setLimit will actually apply.
	return max(h.maxPerHost/4, h.minPerHost)
}

// PreArm proactively arms a host's AIMD back-off and drops it to preArmStart before
// any distress is observed — the proactive counterpart to the reactive WAF-block
// arming in Feedback. A caller invokes it when a host is fingerprinted behind a
// CDN/WAF edge (which commonly arms a rate-based WAF once a scan bursts it), so the
// next phase paces that host from its first request instead of bursting into the edge
// and tripping it. vendor is the fingerprinted edge (for the operator notice; may be
// ""). It pre-arms exactly once per entry (CompareAndSwap on the dedicated preArmed
// flag — NOT armed, so a birth-armed adaptive host still gets the proactive drop and a
// fresh entry created after eviction re-arms). A host already backed off at or below
// the proactive start (by a real block) keeps its lower limit, so a later fingerprint
// never bumps a host that has since backed off further. No-op in static mode and for
// an empty host.
func (h *HostRateLimiter) PreArm(host, vendor string) {
	if !h.PreArmable() || host == "" {
		return
	}
	shard := h.shardFor(host)
	entry := h.getOrCreateEntry(shard, host)
	if entry.tokens == nil {
		return
	}
	if !entry.preArmed.CompareAndSwap(false, true) {
		return // already pre-armed for this entry lifetime
	}
	from := int(entry.limit.Load())
	// Engage AIMD for this host (idempotent if a block already armed it) and mark the
	// run as having at least one armed host so Feedback stops short-circuiting.
	entry.armed.Store(true)
	h.anyArmed.Store(true)
	start := h.preArmStart()
	if from <= start {
		return // already at/below the proactive start — don't raise it, and no notice
	}
	h.setLimit(entry, start)
	zap.L().Debug("HostRateLimiter: CDN/WAF edge fingerprinted — pre-arming pacing",
		zap.String("host", host), zap.String("vendor", vendor),
		zap.Int("from", from), zap.Int("start", start), zap.Int("ceiling", h.ceilingPerHost))
	if h.preArmSink != nil {
		h.preArmSink(PreArmNotice{Host: host, Vendor: vendor, From: from, Start: start, Ceiling: h.ceilingPerHost})
	}
}

// newEntry builds a hostEntry for the limiter's current mode. Static mode gets a
// fixed-cap channel semaphore (the unchanged hot path); adaptive (or WAF-auto-arm)
// mode gets a resizable token pool sized to the ramp ceiling and pre-filled to the
// start limit (MaxPerHost) — under WafAutoArm it stays pinned there until armed.
func (h *HostRateLimiter) newEntry() *hostEntry {
	if !h.usesAdaptiveEntries() {
		return &hostEntry{sem: make(chan struct{}, h.maxPerHost)}
	}
	start := min(max(h.maxPerHost, h.minPerHost), h.ceilingPerHost)
	e := &hostEntry{tokens: make(chan struct{}, h.ceilingPerHost)}
	e.limit.Store(int64(start))
	// Adaptive hosts are armed from birth (adjust from the first request); WAF-auto-arm
	// hosts start unarmed and stay pinned at MaxPerHost until a WAF block arms them.
	e.armed.Store(h.adaptive)
	for i := 0; i < start; i++ {
		e.tokens <- struct{}{}
	}
	return e
}

// Feedback reports the outcome of one request to the host so adaptive mode can
// adjust its concurrency limit. It is a no-op in static mode (and for an evicted
// host). A distress signal (429/503/502/504, connection error, timeout, or a
// confirmed WAF/CDN block) backs the limit off; a healthy completion counts toward
// the next ramp-up. statusCode may be 0 when err != nil (transport-level failure).
// wafBlocked marks the response as a classified WAF/CDN block: it always counts as
// distress, and in WAF-auto-arm mode it is the signal that arms this host's AIMD
// control (before which the host stays pinned at MaxPerHost, unaffected by ordinary
// 429/5xx so a non-WAF scan is never throttled by this path).
func (h *HostRateLimiter) Feedback(host string, statusCode int, err error, wafBlocked bool) {
	if !h.usesAdaptiveEntries() {
		return
	}
	// WAF-auto-arm mode stays dormant until some host trips a WAF block: until then no
	// non-block response can change any limit, so skip the per-host shard lookup and
	// keep Feedback ~free on the common non-WAF hot path. (wafAutoArm implies
	// !adaptive; plain Adaptive arms every host at birth, so anyArmed is moot there.)
	if h.wafAutoArm && !wafBlocked && !h.anyArmed.Load() {
		return
	}
	shard := h.shardFor(host)
	shard.mu.RLock()
	entry, ok := shard.hosts[host]
	shard.mu.RUnlock()
	if !ok || entry.tokens == nil {
		return
	}

	// A confirmed WAF block arms this host's AIMD control (adaptive hosts are armed at
	// birth in newEntry). Until armed, the host stays pinned at MaxPerHost.
	if wafBlocked && entry.armed.CompareAndSwap(false, true) {
		h.anyArmed.Store(true)
		zap.L().Info("HostRateLimiter: WAF/CDN block detected — arming adaptive back-off",
			zap.String("host", host))
	}
	if !entry.armed.Load() {
		return
	}

	if wafBlocked || isDistress(statusCode, err) {
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
