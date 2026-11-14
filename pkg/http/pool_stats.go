package http

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"sync/atomic"

	"go.uber.org/zap"
)

// poolStats accumulates connection-pool telemetry across a scan via httptrace. It
// is a pointer field on Requester so WithContext copies and anonymous views
// (CloneWithoutCredentials) share one instance and the reuse ratio is scan-wide.
// It covers the net/http (retryablehttp) path only; the rawhttp path bypasses
// net/http, so its requests are not traced (a documented blind spot). A single
// ClientTrace is built once and shared across requests — its hooks close over the
// counters, which are fixed — so tracing adds one context wrap per request, not a
// fresh closure set.
type poolStats struct {
	requests   atomic.Int64
	connReused atomic.Int64
	connNew    atomic.Int64
	tlsHands   atomic.Int64

	// connDialed counts connections the transport actually established, tallied in
	// the transport's own DialContext/DialTLSContext wrappers rather than from
	// httptrace.
	//
	// This exists because connNew — httptrace's GotConn with Reused=false — turned
	// out to undercount real connections by ~17x. Go's transport races a dial
	// against waiting for an idle conn; when the wait wins, the freshly dialed
	// connection is parked in the idle pool and handed to a *later* request, which
	// sees Reused=true. The "new" event fires on nobody's trace. Measured against a
	// server counting its own accepts: 7,990 real accepts, 453 reported as new, and
	// a ReuseRatio of 0.975 when the true figure was ~0.56. A churn metric that
	// reads healthy during heavy churn is worse than no metric, so the ratio is
	// derived from this counter instead. connNew is retained for diagnosis — the
	// gap between it and connDialed is itself the misattribution signal.
	connDialed atomic.Int64

	ct *httptrace.ClientTrace
}

func newPoolStats() *poolStats {
	ps := &poolStats{}
	ps.ct = &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				ps.connReused.Add(1)
			} else {
				ps.connNew.Add(1)
			}
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			ps.tlsHands.Add(1)
		},
	}
	return ps
}

// PoolStatsSnapshot is a point-in-time copy of the connection-pool counters.
type PoolStatsSnapshot struct {
	Requests      int64
	ConnNew       int64
	ConnReused    int64
	ConnDialed    int64
	TLSHandshakes int64
}

// RoundTrips is the number of HTTP transactions that obtained a connection.
//
// This is the correct denominator for the churn metrics below, and it is NOT
// Requests: `requests` ticks once per logical doRequest call, while the client
// follows redirects and retries *inside* that call, each of which is its own
// round trip against its own connection. GotConn fires once per round trip, so
// while the new/reused split is misattributed (see poolStats.connDialed), their
// sum is an accurate transaction count.
func (s PoolStatsSnapshot) RoundTrips() int64 { return s.ConnNew + s.ConnReused }

// ReuseRatio is the share of round trips served on an already-open connection:
// (roundTrips - dialed) / roundTrips. A low value signals connection churn, such
// as anonymous clones fragmenting the transport.
//
// Derived from ConnDialed (the transport's real dials) rather than the httptrace
// new/reused split, which systematically misattributes new connections as reuses.
func (s PoolStatsSnapshot) ReuseRatio() float64 {
	rt := s.RoundTrips()
	if rt == 0 {
		return 0
	}
	// A dial can outrun the round trips it serves: the transport races a dial
	// against an idle-conn wait, and a connection that loses that race is parked
	// and may be closed by the idle timeout before carrying anything. That is
	// churn, i.e. ratio 0 — not a negative ratio.
	return float64(max(rt-s.ConnDialed, 0)) / float64(rt)
}

// RoundTripsPerConnection is how many HTTP transactions each established
// connection carried. 1.0 means every transaction paid a fresh TCP (+TLS) setup;
// higher is better. Returns 0 when nothing was dialed through the traced path.
func (s PoolStatsSnapshot) RoundTripsPerConnection() float64 {
	if s.ConnDialed == 0 {
		return 0
	}
	return float64(s.RoundTrips()) / float64(s.ConnDialed)
}

// countDials wraps a transport dial func so every successful connection
// establishment is tallied. Both DialContext and DialTLSContext share the
// signature, so they share this wrapper — and the "successes only" rule (a
// refused connect must not inflate the churn denominator) lives in one place.
func (ps *poolStats) countDials(
	dial func(context.Context, string, string) (net.Conn, error),
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err == nil {
			ps.connDialed.Add(1)
		}
		return conn, err
	}
}

// PoolStats returns a snapshot of the connection-pool counters, or a zero value
// when telemetry is unavailable.
func (r *Requester) PoolStats() PoolStatsSnapshot {
	if r == nil || r.poolStats == nil {
		return PoolStatsSnapshot{}
	}
	ps := r.poolStats
	return PoolStatsSnapshot{
		Requests:      ps.requests.Load(),
		ConnNew:       ps.connNew.Load(),
		ConnReused:    ps.connReused.Load(),
		ConnDialed:    ps.connDialed.Load(),
		TLSHandshakes: ps.tlsHands.Load(),
	}
}

// LogPoolStats logs connection-pool telemetry at info level, a companion to the
// request clusterer's LogStats at end of scan. A no-op when nothing was traced.
func (r *Requester) LogPoolStats() {
	s := r.PoolStats()
	// Dials only happen for requests that went through the traced transport, so
	// Requests == 0 implies every other counter is 0 too.
	if s.Requests == 0 {
		return
	}
	zap.L().Info("HTTP connection pool stats",
		zap.Int64("requests_traced", s.Requests),
		zap.Int64("round_trips", s.RoundTrips()),
		zap.Int64("connections_dialed", s.ConnDialed),
		zap.Int64("connections_new_traced", s.ConnNew),
		zap.Int64("connections_reused_traced", s.ConnReused),
		zap.Int64("tls_handshakes", s.TLSHandshakes),
		zap.Float64("reuse_ratio", s.ReuseRatio()),
		zap.Float64("round_trips_per_conn", s.RoundTripsPerConnection()),
	)
}

// traceContext attaches one attempt's ClientTrace to ctx: a copy of the
// shared pool trace (when telemetry is on) with wroteRequest as its
// WroteRequest hook, so an attempt pays a single context wrap. The shared
// trace is never written: httptrace.WithClientTrace composes any trace
// already on ctx INTO the trace it is given, which on the shared one would
// race across goroutines and chain hooks onto it on every request. A nil
// receiver with a nil hook returns ctx unchanged.
func (p *poolStats) traceContext(ctx context.Context, wroteRequest func(httptrace.WroteRequestInfo)) context.Context {
	var ct httptrace.ClientTrace
	if p != nil {
		ct = *p.ct
		p.requests.Add(1)
	} else if wroteRequest == nil {
		return ctx
	}
	ct.WroteRequest = wroteRequest
	return httptrace.WithClientTrace(ctx, &ct)
}
