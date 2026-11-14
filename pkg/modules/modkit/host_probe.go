package modkit

import (
	"sync"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
)

// Run-once-per-host probes and transient failures (MISS-19).
//
// An active module that probes a host once (a sensitive-file sweep, a
// debug-endpoint check) used to mark the host seen in its DiskSet BEFORE
// probing. When the probe then failed transiently — the host timed out, the
// breaker refused it, the call overran its timeout — the host stayed marked
// and the module never ran there again, so the executor's release-and-retry
// of its per-host claim re-ran a module that immediately returned.
//
// BeginHostProbe replaces that up-front IsSeen. Under the executor the claim
// is held PENDING on the call's requester and committed only once the call
// completes cleanly (no timeout, no transient transport error, no gate
// refusal); a failed call drops it, so the next record of the host probes
// again. A host whose probe failed maxHostProbeAttempts times is claimed
// anyway, so a dead host is not re-probed on every record. Outside the
// executor (module unit tests) the claim is taken immediately, as before.

// maxHostProbeAttempts bounds how many failed probes of one key are retried.
const maxHostProbeAttempts = 2

type pendingHostClaim struct {
	ds  *dedup.DiskSet
	key string
}

type hostProbeState struct {
	mu       sync.Mutex
	pending  map[*http.Requester][]pendingHostClaim
	inFlight map[pendingHostClaim]struct{} // keys some call is probing now
	failures map[pendingHostClaim]int      // failed attempts per (set, key)
}

func (sc *ScanContext) hostProbes() *hostProbeState {
	sc.hostProbeOnce.Do(func() {
		sc.hostProbeState = &hostProbeState{
			pending:  make(map[*http.Requester][]pendingHostClaim),
			inFlight: make(map[pendingHostClaim]struct{}),
			failures: make(map[pendingHostClaim]int),
		}
	})
	return sc.hostProbeState
}

// BeginHostProbe reports whether the module should probe key now. False when
// the key is already claimed in ds, or another call is probing it right now.
// With a nil ds it always probes. Under the executor
// (ScanContext.DeferHostClaims) the claim is registered as pending on client —
// which must be the requester the executor handed the module — and settled by
// SettleHostProbes; otherwise it is taken at once. A claim registered on any
// other requester is never settled and keeps the key in flight, which degrades
// to the old claim-up-front behaviour rather than re-probing every record.
func BeginHostProbe(sc *ScanContext, client *http.Requester, ds *dedup.DiskSet, key string) bool {
	if ds == nil {
		return true
	}
	if sc == nil || !sc.DeferHostClaims || client == nil {
		return !ds.IsSeen(key)
	}
	if ds.Contains(key) {
		return false
	}
	c := pendingHostClaim{ds: ds, key: key}
	st := sc.hostProbes()
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, busy := st.inFlight[c]; busy {
		return false
	}
	st.inFlight[c] = struct{}{}
	st.pending[client] = append(st.pending[client], c)
	sc.hostProbesPending.Add(1)
	return true
}

// SettleHostProbes commits (ok) or drops the pending host claims the module
// call on client registered. A dropped claim counts a failed attempt; past
// maxHostProbeAttempts it is committed anyway.
func (sc *ScanContext) SettleHostProbes(client *http.Requester, ok bool) {
	if sc == nil || client == nil || sc.hostProbesPending.Load() == 0 {
		return
	}
	st := sc.hostProbes()
	st.mu.Lock()
	claims := st.pending[client]
	if len(claims) == 0 {
		st.mu.Unlock()
		return
	}
	delete(st.pending, client)
	sc.hostProbesPending.Add(-int64(len(claims)))
	var commit []pendingHostClaim
	for _, c := range claims {
		delete(st.inFlight, c)
		if ok {
			commit = append(commit, c)
			continue
		}
		st.failures[c]++
		if st.failures[c] >= maxHostProbeAttempts {
			commit = append(commit, c)
		}
	}
	// Commit under the lock: released from inFlight but not yet in ds, a key
	// would otherwise let a concurrent BeginHostProbe start a second probe.
	for _, c := range commit {
		c.ds.IsSeen(c.key)
	}
	st.mu.Unlock()
}
