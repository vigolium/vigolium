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
	// Adaptive default ceiling = MaxPerHost * defaultAdaptiveCeilingFactor, so a
	// healthy host has room to ramp; floor = max(1, 8/10) = 1.
	if h.ceilingPerHost != 8*defaultAdaptiveCeilingFactor || h.minPerHost != 1 {
		t.Fatalf("defaults: ceiling=%d min=%d, want %d/1",
			h.ceilingPerHost, h.minPerHost, 8*defaultAdaptiveCeilingFactor)
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
	h.Feedback(host, FeedbackOutcome{Status: 429})
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("after 429, limit = %d, want 8", got)
	}

	// A second distress within the cooldown is coalesced (no further drop).
	h.Feedback(host, FeedbackOutcome{Status: 503})
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("distress within cooldown should not drop again, got %d", got)
	}

	// A transport error (timeout) also counts as distress after the cooldown.
	time.Sleep(decreaseCooldown + 20*time.Millisecond)
	h.Feedback(host, FeedbackOutcome{Err: errors.New("dial tcp: i/o timeout")})
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
		h.Feedback(host, FeedbackOutcome{Status: 503})
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
	h.Feedback(host, FeedbackOutcome{Status: 429})
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("setup: expected 4, got %d", got)
	}

	// Feed plenty of healthy completions; the limit ramps back toward the ceiling
	// (one +1 step per increaseAfterHealthy+limit clean responses).
	for i := 0; i < 500; i++ {
		h.Feedback(host, FeedbackOutcome{Status: 200})
	}
	if got := h.currentLimit(host); got <= 4 {
		t.Fatalf("expected ramp-up above 4 after healthy traffic, got %d", got)
	}
	// Recovery may now climb past MaxPerHost toward the adaptive ceiling — that is
	// the point of the ramp — but never beyond it.
	if got := h.currentLimit(host); got > h.ceilingPerHost {
		t.Fatalf("ramp-up must not exceed the ceiling %d, got %d", h.ceilingPerHost, got)
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

	h.Feedback(host, FeedbackOutcome{Err: context.Canceled})
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("context cancellation must not back off; got %d, want 8", got)
	}
	// A deadline is a client timeout — the host failed to answer — and backs
	// off (MISS-23). A caller whose own context expired does not report.
	h.Feedback(host, FeedbackOutcome{Err: context.DeadlineExceeded})
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("a client timeout must back off; got %d, want 4", got)
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
			h.Feedback(host, FeedbackOutcome{Status: status})
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
	h.Feedback(host, FeedbackOutcome{Status: 429}) // no-op
	if got := h.currentLimit(host); got != 0 {
		t.Fatalf("static entry has no adaptive limit, got %d", got)
	}
	h.Release(host)
}

func TestWafAutoArm_StaysPinnedUntilBlock(t *testing.T) {
	// WAF-auto-arm mode must behave exactly like the static limiter until a WAF block
	// arms the host: ordinary 429/5xx/transport distress does NOT throttle it.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	// Pinned at MaxPerHost from the start (adaptive entry, not a static semaphore).
	if got := h.currentLimit(host); got != 16 {
		t.Fatalf("unarmed WAF-auto-arm host should be pinned at MaxPerHost=16, got %d", got)
	}
	// A burst of ordinary distress (502/503/timeout) must not change the limit while
	// the host is unarmed — that's the "no behavior change for non-WAF targets" rule.
	// (A 429 is a server throttle, not ordinary distress: it arms the host — MISS-22,
	// see TestFeedback_ThrottlePausesAndHalves.)
	for i := 0; i < 5; i++ {
		time.Sleep(decreaseCooldown + 5*time.Millisecond)
		h.Feedback(host, FeedbackOutcome{Status: 502})
		h.Feedback(host, FeedbackOutcome{Status: 503})
		h.Feedback(host, FeedbackOutcome{Err: errors.New("dial tcp: i/o timeout")})
	}
	if got := h.currentLimit(host); got != 16 {
		t.Fatalf("unarmed host throttled by ordinary distress: limit=%d, want 16", got)
	}
}

func TestWafAutoArm_ArmsAndBacksOffOnWAFBlock(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	// A confirmed WAF block (wafBlocked=true) arms the host and halves the limit.
	h.Feedback(host, FeedbackOutcome{Status: 403, WAFBlocked: true})
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("WAF block should arm + halve 16→8, got %d", got)
	}
	// Now armed, an ordinary 429 backs off further (past the cooldown).
	time.Sleep(decreaseCooldown + 5*time.Millisecond)
	h.Feedback(host, FeedbackOutcome{Status: 429})
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("armed host should back off 8→4 on 429, got %d", got)
	}
	// Healthy completions ramp it back up toward the MaxPerHost ceiling.
	for i := 0; i < 200; i++ {
		h.Feedback(host, FeedbackOutcome{Status: 200})
	}
	if got := h.currentLimit(host); got <= 4 || got > 16 {
		t.Fatalf("armed host should recover toward ceiling 16, got %d", got)
	}
}

func TestPreArm_DropsToStartThenRamps(t *testing.T) {
	// A proactive pre-arm (edge fingerprinted, no block yet) must arm the host and
	// drop it to preArmStart (MaxPerHost/4) so the active phase paces from the first
	// request, then ramp back toward the ceiling on healthy completions.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	if !h.PreArmable() {
		t.Fatal("a WafAutoArm limiter must report PreArmable")
	}

	const host = "edge.example"

	// The once-per-host operator notice fires on the arming call, carrying the drop.
	var notices []PreArmNotice
	h.SetPreArmNotifier(func(n PreArmNotice) { notices = append(notices, n) })

	h.PreArm(host, "cloudfront")
	if got := h.currentLimit(host); got != 4 {
		t.Fatalf("pre-arm should drop 16→4 (MaxPerHost/4), got %d", got)
	}
	if len(notices) != 1 {
		t.Fatalf("want exactly 1 pre-arm notice, got %d", len(notices))
	}
	if n := notices[0]; n.Host != host || n.Vendor != "cloudfront" || n.From != 16 || n.Start != 4 {
		t.Fatalf("notice = %+v, want host=%s vendor=cloudfront from=16 start=4", n, host)
	}

	// A second fingerprint on the same host must not re-arm or re-notify.
	h.PreArm(host, "cloudfront")
	if len(notices) != 1 {
		t.Fatalf("pre-arm notice must fire once per host, got %d", len(notices))
	}

	// A healthy run ramps the paced host back up toward the MaxPerHost ceiling.
	for i := 0; i < 400; i++ {
		h.Feedback(host, FeedbackOutcome{Status: 200})
	}
	if got := h.currentLimit(host); got <= 4 || got > 16 {
		t.Fatalf("pre-armed host should ramp back toward ceiling 16, got %d", got)
	}
}

func TestPreArm_LeavesBlockArmedHostAlone(t *testing.T) {
	// A real WAF block backs a host off toward the floor; a later edge fingerprint
	// must NOT bump that host back up to preArmStart. The arm-once guard keeps the
	// lower (block-driven) limit.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, MinPerHost: 2, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "edge.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	for i := 0; i < 6; i++ {
		time.Sleep(decreaseCooldown + 5*time.Millisecond)
		h.Feedback(host, FeedbackOutcome{Status: 403, WAFBlocked: true})
	}
	blocked := h.currentLimit(host)
	if blocked >= 16 || blocked > 4 {
		t.Fatalf("repeated blocks should back off below preArmStart(4), got %d", blocked)
	}

	h.PreArm(host, "cloudfront") // already armed — must be a no-op, not a bump up to 4
	if got := h.currentLimit(host); got != blocked {
		t.Fatalf("PreArm bumped a block-armed host: %d → %d", blocked, got)
	}
}

func TestPreArm_DisabledKeepsReactiveBackoff(t *testing.T) {
	// --no-waf-pacing (DisablePreArm) turns off the proactive pre-arm but must
	// leave the reactive WAF-block back-off intact.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, DisablePreArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	if h.PreArmable() {
		t.Fatal("DisablePreArm must make the limiter non-PreArmable")
	}

	const host = "edge.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host)

	var notices []PreArmNotice
	h.SetPreArmNotifier(func(n PreArmNotice) { notices = append(notices, n) })

	h.PreArm(host, "cloudfront") // must be a no-op — no throttle, no notice
	if got := h.currentLimit(host); got != 16 {
		t.Fatalf("proactive pre-arm should be disabled (pinned at 16), got %d", got)
	}
	if len(notices) != 0 {
		t.Fatalf("disabled pre-arm must not notify, got %d", len(notices))
	}

	// Reactive path still works: a confirmed WAF block arms + halves.
	h.Feedback(host, FeedbackOutcome{Status: 403, WAFBlocked: true})
	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("reactive WAF back-off must still apply (16→8), got %d", got)
	}
}

func TestPreArm_NoOpInStaticMode(t *testing.T) {
	// The static limiter has no adaptive token pool, so PreArm is a no-op and never
	// throttles — a scan without WafAutoArm/Adaptive is unaffected.
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 16, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	if h.PreArmable() {
		t.Fatal("a static limiter must not report PreArmable")
	}
	const host = "edge.example"
	h.PreArm(host, "cloudfront") // must not panic and must not create/throttle an adaptive entry

	// Full static concurrency is still available: MaxPerHost non-blocking acquires.
	for i := 0; i < 16; i++ {
		if !tryAcquireEntry(h.getOrCreateEntry(h.shardFor(host), host)) {
			t.Fatalf("static host throttled after PreArm: slot %d unavailable", i)
		}
	}
	for i := 0; i < 16; i++ {
		h.Release(host)
	}
}

// The adaptive ramp ceiling defaults by mode. Adaptive is an opt-in to
// concurrency discovery so it gets headroom; WAF-auto-arm is a throttle, so a
// host recovering from a block returns to MaxPerHost and stops there.
func TestResolveCeilingPerHost(t *testing.T) {
	tests := []struct {
		name       string
		maxPerHost int
		configured int
		adaptive   bool
		want       int
	}{
		{"adaptive default gets headroom", 40, 0, true, 40 * defaultAdaptiveCeilingFactor},
		{"non-adaptive default pins to max", 40, 0, false, 40},
		{"explicit ceiling wins when adaptive", 40, 100, true, 100},
		{"explicit ceiling wins when not adaptive", 40, 100, false, 100},
		// A ceiling below the start would strand the token pool below its initial
		// fill, so it is floored at MaxPerHost rather than honored.
		{"ceiling below max is floored", 40, 10, true, 40},
		{"negative ceiling treated as unset", 40, -5, true, 40 * defaultAdaptiveCeilingFactor},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := HostRateLimiterConfig{
				MaxPerHost:     tc.maxPerHost,
				CeilingPerHost: tc.configured,
				Adaptive:       tc.adaptive,
			}
			if got := resolveCeilingPerHost(cfg); got != tc.want {
				t.Fatalf("resolveCeilingPerHost(max=%d, ceiling=%d, adaptive=%v) = %d, want %d",
					tc.maxPerHost, tc.configured, tc.adaptive, got, tc.want)
			}
		})
	}
}

// The regression this guards: with ceiling == MaxPerHost the AIMD controller was
// a one-way ratchet — it could only ever back a host OFF, so nothing could
// discover that a host tolerates more than the configured concurrency.
func TestAdaptive_RampsAboveMaxPerHost(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	_ = h.Acquire(context.Background(), host)
	h.Release(host)

	if got := h.currentLimit(host); got != 8 {
		t.Fatalf("setup: expected to start at MaxPerHost=8, got %d", got)
	}
	for i := 0; i < 2000; i++ {
		h.Feedback(host, FeedbackOutcome{Status: 200})
	}
	if got := h.currentLimit(host); got <= 8 {
		t.Fatalf("healthy host must ramp above MaxPerHost=8, got %d", got)
	}
	if got := h.currentLimit(host); got > h.ceilingPerHost {
		t.Fatalf("ramp must stop at the ceiling %d, got %d", h.ceilingPerHost, got)
	}
}

// WAF auto-arm is a throttle, not a ramp: a host that trips a block, backs off,
// then recovers must return to MaxPerHost and never exceed it. A WAF block is
// not licence to raise concurrency.
func TestWafAutoArm_RecoveryStopsAtMaxPerHost(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, WafAutoArm: true, EvictInterval: time.Hour,
	})
	defer func() { _ = h.Close() }()

	if h.ceilingPerHost != 8 {
		t.Fatalf("waf-auto-arm ceiling = %d, want MaxPerHost=8", h.ceilingPerHost)
	}

	const host = "waf.example"
	_ = h.Acquire(context.Background(), host)
	h.Release(host)

	// A confirmed block arms AIMD and backs the host off.
	h.Feedback(host, FeedbackOutcome{Status: 403, WAFBlocked: true})
	if got := h.currentLimit(host); got >= 8 {
		t.Fatalf("expected back-off below 8 after a WAF block, got %d", got)
	}
	for i := 0; i < 2000; i++ {
		h.Feedback(host, FeedbackOutcome{Status: 200})
	}
	if got := h.currentLimit(host); got > 8 {
		t.Fatalf("waf-armed recovery must stop at MaxPerHost=8, got %d", got)
	}
}

// The transport sizes its idle-connection pool from this accessor, so it must
// report the ramp ceiling the limiter actually resolved — not the value it
// starts at.
func TestCeilingPerHostAccessor(t *testing.T) {
	adaptive := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, Adaptive: true, EvictInterval: time.Hour,
	})
	defer func() { _ = adaptive.Close() }()
	if got := adaptive.CeilingPerHost(); got != 8*defaultAdaptiveCeilingFactor {
		t.Errorf("adaptive CeilingPerHost() = %d, want %d", got, 8*defaultAdaptiveCeilingFactor)
	}

	static := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost: 8, EvictInterval: time.Hour,
	})
	defer func() { _ = static.Close() }()
	if got := static.CeilingPerHost(); got != 8 {
		t.Errorf("static CeilingPerHost() = %d, want MaxPerHost=8", got)
	}
}
