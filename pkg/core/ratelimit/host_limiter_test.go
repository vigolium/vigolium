package ratelimit

import (
	"container/heap"
	"context"
	"testing"
	"time"
)

func TestDefaultHostRateLimiterConfig(t *testing.T) {
	cfg := DefaultHostRateLimiterConfig()
	if cfg.MaxPerHost != 20 {
		t.Errorf("MaxPerHost = %d, want 20", cfg.MaxPerHost)
	}
	if cfg.MaxEntries != 1000 {
		t.Errorf("MaxEntries = %d, want 1000", cfg.MaxEntries)
	}
	if cfg.EvictAfter != 30*time.Second {
		t.Errorf("EvictAfter = %v, want 30s", cfg.EvictAfter)
	}
	if cfg.AcquireTimeout != 30*time.Second {
		t.Errorf("AcquireTimeout = %v, want 30s", cfg.AcquireTimeout)
	}
}

func TestNewHostRateLimiter_AppliesDefaults(t *testing.T) {
	// A zero config must be backfilled with defaults, not left as zeros (a
	// zero MaxPerHost semaphore would deadlock the first Acquire).
	h := NewHostRateLimiter(HostRateLimiterConfig{})
	defer func() { _ = h.Close() }()

	if h.maxPerHost != 20 {
		t.Errorf("maxPerHost = %d, want 20", h.maxPerHost)
	}
	if h.maxEntries != 1000 {
		t.Errorf("maxEntries = %d, want 1000", h.maxEntries)
	}
}

func TestHostRateLimiter_AcquireRelease(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost:    2,
		EvictInterval: time.Hour, // keep the eviction loop out of the way
	})
	defer func() { _ = h.Close() }()

	const host = "example.com"

	// Fill both slots.
	for i := 0; i < 2; i++ {
		if err := h.Acquire(context.Background(), host); err != nil {
			t.Fatalf("Acquire #%d: %v", i, err)
		}
	}

	// Third acquire must block; a short context should expire.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.Acquire(ctx, host); err == nil {
		t.Fatal("expected Acquire to block past MaxPerHost, but it succeeded")
	}

	// Free a slot, then acquisition should succeed again.
	h.Release(host)
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
}

func TestHostRateLimiter_AcquireContextCancel(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{MaxPerHost: 1, EvictInterval: time.Hour})
	defer func() { _ = h.Close() }()

	const host = "h.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("initial Acquire: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.Acquire(ctx, host); err == nil {
		t.Fatal("expected error from a cancelled context")
	}
}

func TestHostRateLimiter_AcquireWithTimeout(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost:     1,
		AcquireTimeout: 20 * time.Millisecond,
		EvictInterval:  time.Hour,
	})
	defer func() { _ = h.Close() }()

	const host = "slow.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("initial Acquire: %v", err)
	}

	start := time.Now()
	err := h.AcquireWithTimeout(host)
	if err == nil {
		t.Fatal("expected AcquireWithTimeout to fail when no slot is free")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("AcquireWithTimeout blocked too long: %v", elapsed)
	}
}

func TestHostRateLimiter_ReleaseUnknownHost(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{MaxPerHost: 1, EvictInterval: time.Hour})
	defer func() { _ = h.Close() }()

	// Releasing a host that was never acquired must be a safe no-op.
	h.Release("never-seen.example")
}

func TestHostRateLimiter_Stats(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{MaxPerHost: 1, EvictInterval: time.Hour})
	defer func() { _ = h.Close() }()

	for _, host := range []string{"a.example", "b.example", "c.example"} {
		if err := h.Acquire(context.Background(), host); err != nil {
			t.Fatalf("Acquire %s: %v", host, err)
		}
	}

	tracked, maxEntries := h.Stats()
	if tracked != 3 {
		t.Errorf("tracked hosts = %d, want 3", tracked)
	}
	if maxEntries != 1000 {
		t.Errorf("maxEntries = %d, want 1000", maxEntries)
	}
}

func TestHostRateLimiter_ShardForDeterministic(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{EvictInterval: time.Hour})
	defer func() { _ = h.Close() }()

	hosts := []string{"a.example", "b.example", "c.example", "repeat.example"}
	first := make(map[string]*hostShard, len(hosts))
	for _, host := range hosts {
		first[host] = h.shardFor(host)
	}
	// Repeated lookups must always route a host to the same shard.
	for i := 0; i < 5; i++ {
		for _, host := range hosts {
			if got := h.shardFor(host); got != first[host] {
				t.Fatalf("shardFor(%q) not stable across calls", host)
			}
		}
	}
}

func TestHostRateLimiter_EvictsIdleHosts(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{
		MaxPerHost:    1,
		EvictAfter:    10 * time.Millisecond,
		EvictInterval: 10 * time.Millisecond,
	})
	defer func() { _ = h.Close() }()

	const host = "ephemeral.example"
	if err := h.Acquire(context.Background(), host); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	h.Release(host) // free the slot so the entry becomes evictable

	deadline := time.After(2 * time.Second)
	for {
		if tracked, _ := h.Stats(); tracked == 0 {
			return // evicted as expected
		}
		select {
		case <-deadline:
			t.Fatal("idle host was not evicted within 2s")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestHostRateLimiter_Close(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{MaxPerHost: 1, EvictInterval: 10 * time.Millisecond})
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// After Close the shard maps are cleared; Stats must still be callable.
	if tracked, _ := h.Stats(); tracked != 0 {
		t.Errorf("tracked after Close = %d, want 0", tracked)
	}
}

func TestHostHeap_OrdersByLastUsed(t *testing.T) {
	h := &hostHeap{}
	heap.Init(h)
	heap.Push(h, &heapEntry{host: "a", lastUsed: 30})
	heap.Push(h, &heapEntry{host: "b", lastUsed: 10})
	heap.Push(h, &heapEntry{host: "c", lastUsed: 20})

	if h.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", h.Len())
	}

	// Min-heap on lastUsed: pops ascend 10, 20, 30.
	want := []string{"b", "c", "a"}
	for i, w := range want {
		got := heap.Pop(h).(*heapEntry)
		if got.host != w {
			t.Errorf("pop #%d = %q, want %q", i, got.host, w)
		}
	}
}
