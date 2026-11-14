package knownissuescan

import (
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
)

// requestCounter is a nuclei progress sink that counts the requests nuclei
// sends. nuclei runs its own HTTP stack outside the egress gate, so this is
// how its traffic reaches --max-requests: the runner registers the counter as
// tracked (soft) traffic, the budget watcher samples it, and the scan context
// is cancelled once the scan-wide limit is passed.
type requestCounter struct {
	n *atomic.Int64
}

var _ progress.Progress = requestCounter{}

func (requestCounter) Stop()                   {}
func (requestCounter) Init(int64, int, int64)  {}
func (requestCounter) AddToTotal(int64)        {}
func (requestCounter) IncrementMatched()       {}
func (requestCounter) IncrementErrorsBy(int64) {}

// IncrementRequests counts one sent request.
func (c requestCounter) IncrementRequests() { c.n.Add(1) }

// SetRequests adds count sent requests (nuclei's "increment by delta").
func (c requestCounter) SetRequests(count uint64) {
	// #nosec G115 -- a per-call request delta never approaches MaxInt64.
	c.n.Add(int64(count))
}

// IncrementFailedRequestsBy counts requests that were attempted and failed:
// they still reached the wire (or tried to), so they count against a budget.
func (c requestCounter) IncrementFailedRequestsBy(count int64) { c.n.Add(count) }
