package ratelimit

import (
	"context"
	"testing"
	"time"
)

// MISS-22: a 429 pauses the host (acquires wait ≥ ~1s) and halves its limit,
// even in WAF-auto-arm mode before any WAF block.
func TestFeedbackWith_ThrottlePausesAndHalves(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{MaxPerHost: 8, WafAutoArm: true})
	defer func() { _ = h.Close() }()
	ctx := context.Background()
	const host = "a.test"
	if err := h.Acquire(ctx, host); err != nil {
		t.Fatal(err)
	}
	h.Release(host)
	before, _ := h.CurrentLimit(host)

	h.FeedbackWith(host, FeedbackOutcome{Status: 429})
	if h.PausedUntil(host).IsZero() {
		t.Fatal("429 did not pause the host")
	}
	after, _ := h.CurrentLimit(host)
	if after >= before || after != max(before/2, 1) {
		t.Errorf("limit %d -> %d, want halved", before, after)
	}
	start := time.Now()
	if err := h.AcquireWithTimeoutContext(ctx, host); err != nil {
		t.Fatal(err)
	}
	h.Release(host)
	if waited := time.Since(start); waited < 900*time.Millisecond {
		t.Errorf("acquire waited %v, want >= ~1s", waited)
	}
}

// A 503 needs a Retry-After to count as a throttle; Retry-After sets the pause.
func TestFeedbackWith_RetryAfterAndPlain503(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{MaxPerHost: 4})
	defer func() { _ = h.Close() }()
	h.FeedbackWith("b.test", FeedbackOutcome{Status: 503})
	if !h.PausedUntil("b.test").IsZero() {
		t.Error("a plain 503 must not pause")
	}
	h.FeedbackWith("b.test", FeedbackOutcome{Status: 503, RetryAfter: 3 * time.Second})
	until := h.PausedUntil("b.test")
	if d := time.Until(until); d < 2500*time.Millisecond || d > 3500*time.Millisecond {
		t.Errorf("pause = %v, want ~3s", d)
	}
	// Clamped to 60s.
	h.FeedbackWith("c.test", FeedbackOutcome{Status: 429, RetryAfter: time.Hour})
	if d := time.Until(h.PausedUntil("c.test")); d > 61*time.Second {
		t.Errorf("pause = %v, want clamped to 60s", d)
	}
	// Cancellation unblocks a paused acquire.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.Acquire(ctx, "c.test"); err == nil {
		t.Error("acquire on a paused host must honour ctx")
	}
}
