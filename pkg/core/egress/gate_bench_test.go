package egress

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/ratelimit"
)

func benchGate(b *testing.B) *Gate {
	b.Helper()
	cfg := ratelimit.DefaultHostRateLimiterConfig()
	cfg.MaxPerHost = 64
	cfg.AcquireTimeout = 5 * time.Second
	hosts := ratelimit.NewHostRateLimiter(cfg)
	b.Cleanup(func() { _ = hosts.Close() })
	breaker := hosterrors.New(30, 0, nil)
	b.Cleanup(breaker.Close)
	return New(Config{Hosts: hosts, Breaker: breaker}).WithBudget(NewBudget(0, 1<<62))
}

// BenchmarkGateAcquire is the per-wire-attempt admission cost with host slots,
// the breaker and a per-host budget all on: Acquire then release a success.
func BenchmarkGateAcquire(b *testing.B) {
	g := benchGate(b)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		release, err := g.Acquire(ctx, "a.test:443", LaneNormal)
		if err != nil {
			b.Fatal(err)
		}
		release(Outcome{})
	}
}

// BenchmarkGateDo is the shared requester's path: one Do with no retry.
func BenchmarkGateDo(b *testing.B) {
	g := benchGate(b)
	ctx := context.Background()
	send := func(int, bool) error { return nil }
	b.ReportAllocs()
	for b.Loop() {
		if _, err := g.Do(ctx, "a.test:443", LaneNormal, RetryPolicy{}, send); err != nil {
			b.Fatal(err)
		}
	}
}
