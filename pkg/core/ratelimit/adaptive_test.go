package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// currentLimit reads a host's adaptive limit (0 if the host/entry isn't adaptive).
func (h *HostRateLimiter) currentLimit(host string) int {
	shard := h.shardFor(host)
	shard.mu.RLock()
	entry, ok := shard.hosts[host]
	shard.mu.RUnlock()
	if !ok || entry.tokens == nil {
		return 0
	}
	return int(entry.limit.Load())
}

func TestAdaptive_StartsAtMaxPerHost(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("adaptive host should start at MaxPerHost=8, got %d", got)
	}
	// Default ceiling = MaxPerHost; floor = max(1, 8/10) = 1.
	if h.ceilingPerHost != 8 || h.minPerHost != 1 {
		t.Fatalf("defaults: ceiling=%d min=%d, want 8/1", h.ceilingPerHost, h.minPerHost)
	}
}

func TestAdaptive_RespectsCurrentLimit(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 2, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	// Acquire both slots; a third must block (the resizable pool caps at the limit).
	for i := 0; i < 2; i++ {
		if err := h.Acquire(context.Background(), host); err != nil {
			t.Fatalf("Acquire #%d: %v", i, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.Acquire(ctx, host); err == nil {
		t.Fatal("expected Acquire to block past the current adaptive limit")
	}
	h.Release(host)
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
}

func TestAdaptive_BacksOffOnDistress(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	// Materialize the entry.
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	// A 429 halves the limit (16 -> 8).
	h.Feedback(host, 429, nil)
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("after 429, limit = %d, want 8", got)
	}

	// A second distress within the cooldown is coalesced (no further drop).
	h.Feedback(host, 503, nil)
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("distress within cooldown should not drop again, got %d", got)
	}

	// A transport error (timeout) also counts as distress after the cooldown.
	time.Sleep(decreaseCooldown + 20*time.Millisecond)
	h.Feedback(host, 0, errors.New("dial tcp: i/o timeout"))
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("after timeout, limit = %d, want 4", got)
	}
}

func TestAdaptive_BackoffFlooredAtMin(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 4, MinPerHost: 2, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	_ = h.Acquire(context.Background(), host)
	h.Release(host)

	for i := 0; i < 5; i++ {
		h.Feedback(host, 503, nil)
		time.Sleep(decreaseCooldown + 10*time.Millisecond)
	}
	if got := h.currentLimit(host); got != 2 {
		t.Fatalf("limit should floor at MinPerHost=2, got %d", got)
	}
}

func TestAdaptive_RecoversWhenHealthy(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	_ = h.Acquire(context.Background(), host)
	h.Release(host)

	// Drop to 4.
	h.Feedback(host, 429, nil)
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("setup: expected 4, got %d", got)
	}

	// Feed plenty of healthy completions; the limit ramps back toward the ceiling
	// (one +1 step per increaseAfterHealthy+limit clean responses).
	for i := 0; i < 500; i++ {
		h.Feedback(host, 200, nil)
	}
	if got := h.currentLimit(host); got <= 4 {
		t.Fatalf("expected ramp-up above 4 after healthy traffic, got %d", got)
	}
	if got := h.currentLimit(host); got > 8 {
		t.Fatalf("ramp-up must not exceed the ceiling 8, got %d", got)
	}
}

func TestAdaptive_ContextCancelNotDistress(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	_ = h.Acquire(context.Background(), host)
	h.Release(host)

	h.Feedback(host, 0, context.Canceled)
	h.Feedback(host, 0, context.DeadlineExceeded)
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("context cancellation must not back off; got %d, want 8", got)
	}
}

func TestAdaptive_ConcurrentAcquireReleaseFeedback(t *testing.T) {
	// Hammer one host with concurrent acquires/releases while feedback resizes the
	// pool, then verify the invariant once quiescent: available tokens + zero
	// in-flight == current limit (no leaked or duplicated tokens).
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 12, MinPerHost: 2, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "stress.example"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	worker := func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			actx, acancel := context.WithTimeout(ctx, 100*time.Millisecond)
			if err := h.Acquire(actx, host); err == nil {
				h.Release(host)
			}
			acancel()
		}
	}
	for i := 0; i < 24; i++ {
		go worker()
	}
	// Drive resizes from multiple goroutines.
	feeder := func(status int) {
		for {
			select {
			case <-done:
				return
			default:
			}
			h.Feedback(host, status, nil)
			time.Sleep(time.Millisecond)
		}
	}
	go feeder(503) // back-off pressure
	go feeder(200) // recovery pressure

	time.Sleep(1 * time.Second)
	close(done)
	time.Sleep(150 * time.Millisecond) // let workers drain

	// Quiescent invariant: all tokens returned, none in flight.
	shard := h.shardFor(host)
	shard.mu.RLock()
	entry := shard.hosts[host]
	shard.mu.RUnlock()
	if entry == nil {
		t.Fatal("entry vanished")
	}
	if inflight := entry.inflight.Load(); inflight != 0 {
		t.Fatalf("inflight should be 0 at rest, got %d", inflight)
	}
	limit := int(entry.limit.Load())
	avail := len(entry.tokens)
	if avail != limit {
		t.Fatalf("token-pool invariant broken: available=%d limit=%d (debt=%d)", avail, limit, entry.debt.Load())
	}
	if limit < h.minPerHost || limit > h.ceilingPerHost {
		t.Fatalf("limit %d out of bounds [%d,%d]", limit, h.minPerHost, h.ceilingPerHost)
	}
}

func TestStaticMode_NoFeedbackEffect(t *testing.T) {
	// Feedback is a no-op in static mode and must not panic or change behavior.
	h := NewHostRateLimiter(HostRateLimiterConfig{MaxPerHost: 4, EvictInterval: time.Hour})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Feedback(host, 429, nil) // no-op
	if got := h.currentLimit(host); got != 0 {
		t.Fatalf("static entry has no adaptive limit, got %d", got)
	}
	h.Release(host)
}
