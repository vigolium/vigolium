package http

// TRACK-B STUB. Track A owns these APIs (arch-enhanced-impl.md, "Cross-track
// contracts"); Track B consumes them in pkg/core. Signatures match the
// contract exactly. The integrator keeps Track A's implementation and deletes
// this file plus the two marked struct fields / the one marked line in
// WithAbandonFlag.

import (
	"errors"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// CallStats counts what happened to one module call's requests: responses
// received while the host was throttling (429/503), requests refused because
// the call was abandoned, and requests the egress gate refused.
type CallStats struct {
	Throttled atomic.Int64
	Abandoned atomic.Int64
	Refused   atomic.Int64
	// TransportErrors (TRACK-B ADDITION to the contract struct — keep it when
	// reconciling): requests of this call that failed transiently (DNS,
	// refused, timeout, TLS, reset, quarantined host). The executor settles
	// run-once host probes on it (MISS-19).
	TransportErrors atomic.Int64
}

// noteCallError counts a transient send failure on this per-call clone.
func (r *Requester) noteCallError(err error) {
	if err == nil || r == nil || r.callStats == nil {
		return
	}
	if errors.Is(err, ErrRequestAbandoned) {
		return // the call was given up on; the executor already knows
	}
	if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		r.callStats.TransportErrors.Add(1)
		return
	}
	switch ClassifyTransportError(err) {
	case TransportErrDNS, TransportErrRefused, TransportErrTimeout, TransportErrTLS, TransportErrReset:
		r.callStats.TransportErrors.Add(1)
	}
}

// CallStats returns this per-call clone's stats, or nil on a requester that is
// not a per-call clone.
func (r *Requester) CallStats() *CallStats {
	if r == nil {
		return nil
	}
	return r.callStats
}

// WithBaseline returns a shallow clone carrying the record's unmodified
// request/response, used as the breaker's recovery probe (MISS-24).
func (r *Requester) WithBaseline(rr *httpmsg.HttpRequestResponse) *Requester {
	if r == nil || rr == nil {
		return r
	}
	clone := *r
	clone.baseline = rr
	return &clone
}
