package core

import (
	"sort"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/work"
)

// Drop reasons: why an input item ended without its record in the store.
const (
	DropFetchError  = "fetch_error"  // the request failed in transport (DNS, connect, TLS, timeout)
	DropBlocked     = "blocked"      // the answer was a WAF / bot-wall page (see ExecutorConfig.KeepBlocked)
	DropBudget      = "budget"       // the request budget refused the send (--max-requests[-per-host])
	DropQuarantined = "quarantined"  // the host was quarantined as unresponsive
	DropStoreError  = "store_error"  // the database refused the write
	DropOutOfScope  = "out_of_scope" // the answer was out of scope and scope applies on ingest
)

// SkipStaticFile is the OnUnanswered reason for an item the static-file
// filter refused before the send. It is not a drop-ledger reason: the filter
// is policy, not a failure, and the ledger counts failures.
const SkipStaticFile = "static_file"

// SkipWriteTemplate is the OnUnanswered reason for a stored request-only stub
// with a state-changing method that the write-template guard refused to send
// (ExecutorConfig.AllowWrites). Policy, like SkipStaticFile.
const SkipWriteTemplate = "write_template"

// dropReasons is the closed set, in the order a ledger stores them.
var dropReasons = [...]string{DropFetchError, DropBlocked, DropBudget, DropQuarantined, DropStoreError, DropOutOfScope}

// MaxDropSamples bounds the dropped items one run keeps as examples. Enough to
// name the pattern; the counts carry the size.
const MaxDropSamples = 20

// DropSample is one dropped item, for reporting.
type DropSample struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// dropLedger counts drops by reason and keeps the first MaxDropSamples. A dead
// host can drop every queued item, so the hot path is one atomic add, and the
// sample lock is taken only while there is room for another sample.
type dropLedger struct {
	counts  [len(dropReasons)]atomic.Int64
	sampled atomic.Int64

	mu      sync.Mutex
	samples []DropSample
}

func (d *dropLedger) note(url, reason string, err error) {
	for i, r := range dropReasons {
		if r == reason {
			d.counts[i].Add(1)
			break
		}
	}
	if d.sampled.Load() >= MaxDropSamples {
		return
	}
	d.mu.Lock()
	if len(d.samples) < MaxDropSamples {
		s := DropSample{URL: url, Reason: reason}
		if err != nil {
			s.Detail = err.Error()
		}
		d.samples = append(d.samples, s)
		d.sampled.Store(int64(len(d.samples)))
	}
	d.mu.Unlock()
}

func (d *dropLedger) reasons() map[string]int64 {
	out := map[string]int64{}
	for i, r := range dropReasons {
		if n := d.counts[i].Load(); n > 0 {
			out[r] = n
		}
	}
	return out
}

func (d *dropLedger) sampleList() []DropSample {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]DropSample(nil), d.samples...)
}

// noteDrop records that an item stored nothing, and why.
func (e *Executor) noteDrop(url, reason string, err error) { e.drops.note(url, reason, err) }

// noteUnanswered tells the OnUnanswered callback that item ends without a
// baseline response, and why.
func (e *Executor) noteUnanswered(item *work.WorkItem, reason string, err error) {
	if e.cfg.OnUnanswered != nil {
		e.cfg.OnUnanswered(item, reason, err)
	}
}

// DropReasons returns how many input items ended without a stored record, per
// reason (the Drop* constants). Reasons with no drops are absent.
func (e *Executor) DropReasons() map[string]int64 { return e.drops.reasons() }

// DropSamples returns the first few dropped items, in the order they dropped.
func (e *Executor) DropSamples() []DropSample { return e.drops.sampleList() }

// SortedDropReasons orders reasons most drops first, ties by name, so a report
// leads with the cause worth fixing.
func SortedDropReasons(reasons map[string]int64) []string {
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if reasons[keys[i]] != reasons[keys[j]] {
			return reasons[keys[i]] > reasons[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}
