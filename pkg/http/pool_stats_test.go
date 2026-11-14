package http

import (
	"context"
	"net/http/httptrace"
	"testing"
)

// ConnDialed (real transport dials) drives the ratio, and RoundTrips — not
// Requests — is the denominator: one logical request can span many round trips
// via redirects/retries, so mixing the two units skews the result.
func TestPoolStatsReuseRatioUsesDialsOverRoundTrips(t *testing.T) {
	// The regression this guards: httptrace reported 453 new / 17784 reused
	// (ratio 0.975) while the server actually accepted 7990 connections.
	s := PoolStatsSnapshot{Requests: 18309, ConnNew: 453, ConnReused: 17784, ConnDialed: 7990}
	if rt := s.RoundTrips(); rt != 18237 {
		t.Fatalf("round trips = %d, want 18237 (new+reused)", rt)
	}
	if got := s.ReuseRatio(); got < 0.56 || got > 0.57 {
		t.Errorf("reuse ratio = %v, want ~0.56 (dial-based), not 0.975 (trace-based)", got)
	}
	if got := s.RoundTripsPerConnection(); got < 2.27 || got > 2.29 {
		t.Errorf("round trips per connection = %v, want ~2.28", got)
	}
}

// Nothing dialed and nothing traced is 0, not a divide-by-zero.
func TestPoolStatsReuseRatioEmpty(t *testing.T) {
	s := PoolStatsSnapshot{}
	if got := s.ReuseRatio(); got != 0 {
		t.Errorf("empty reuse ratio = %v, want 0", got)
	}
	if got := s.RoundTripsPerConnection(); got != 0 {
		t.Errorf("empty round trips per connection = %v, want 0", got)
	}
}

// Every round trip opening its own connection is 0 reuse — and a dial that never
// carried a round trip (parked by the transport, then idled out) must not push the
// ratio negative.
func TestPoolStatsReuseRatioAllChurn(t *testing.T) {
	s := PoolStatsSnapshot{Requests: 50, ConnNew: 50, ConnDialed: 50}
	if got := s.ReuseRatio(); got != 0 {
		t.Errorf("reuse ratio = %v, want 0 when every round trip dials", got)
	}
	s2 := PoolStatsSnapshot{Requests: 10, ConnNew: 10, ConnDialed: 25}
	if got := s2.ReuseRatio(); got != 0 {
		t.Errorf("reuse ratio = %v, want 0 when dials exceed round trips", got)
	}
}

func TestPoolStatsTraceCounts(t *testing.T) {
	ps := newPoolStats()
	// GotConn hooks feed the reused/new counters.
	ps.connReused.Add(2)
	ps.connNew.Add(2)
	r := &Requester{poolStats: ps}
	snap := r.PoolStats()
	if snap.ConnReused != 2 || snap.ConnNew != 2 {
		t.Fatalf("snapshot = %+v", snap)
	}
	// 4 round trips, 2 of them dialed -> half were reused.
	snap.ConnDialed = 2
	if snap.ReuseRatio() != 0.5 {
		t.Errorf("reuse ratio = %v, want 0.5", snap.ReuseRatio())
	}
	// A nil-poolStats requester returns a zero snapshot, not a panic.
	if (&Requester{}).PoolStats() != (PoolStatsSnapshot{}) {
		t.Error("nil poolStats should yield a zero snapshot")
	}
}

// Each attempt gets its own trace copy carrying the attempt's WroteRequest
// hook, and a trace already on the context is composed into that copy, never
// into the shared pool trace: composing into the shared one raced across
// goroutines and chained hooks onto it on every request.
func TestPoolStatsTraceContextLeavesSharedTraceUntouched(t *testing.T) {
	ps := newPoolStats()
	before := ps.ct.WroteRequest
	var outerWrote, attemptWrote int
	outer := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { outerWrote++ },
	})
	for range 3 {
		got := httptrace.ContextClientTrace(ps.traceContext(outer, func(httptrace.WroteRequestInfo) { attemptWrote++ }))
		if got == ps.ct {
			t.Fatal("traceContext attached the shared trace itself")
		}
		if got.WroteRequest == nil || got.GotConn == nil {
			t.Fatal("attempt trace lost a hook")
		}
		got.WroteRequest(httptrace.WroteRequestInfo{})
	}
	if outerWrote != 3 || attemptWrote != 3 {
		t.Fatalf("hooks fired outer=%d attempt=%d, want 3 each", outerWrote, attemptWrote)
	}
	if (ps.ct.WroteRequest == nil) != (before == nil) {
		t.Fatal("shared pool trace was mutated by composition")
	}
	if ps.requests.Load() != 3 {
		t.Errorf("requests = %d, want 3", ps.requests.Load())
	}
	// No telemetry and no hook: nothing to attach.
	var nilStats *poolStats
	if nilStats.traceContext(outer, nil) != outer {
		t.Error("nil poolStats with no hook should return ctx unchanged")
	}
}
