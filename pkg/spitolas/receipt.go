package spitolas

import "github.com/vigolium/vigolium/pkg/spitolas/internal/network"

// CaptureReceipt is what a browser run actually retained. Separate from
// RecordsSaved (a count) because "capture was configured" and "records reached
// the database" are different facts, and a caller that only knows the first
// must not report the second.
type CaptureReceipt struct {
	Enabled         bool `json:"enabled"`          // capture actually ran
	BodiesRetained  bool `json:"bodies_retained"`  // response bodies were kept
	HeadersRetained bool `json:"headers_retained"` // response headers were kept
	Accepted        int  `json:"accepted"`         // entries the writer admitted
	Persisted       int  `json:"persisted"`        // rows the repository confirmed (spec-ingested endpoints included)
	Refused         int  `json:"refused"`          // entries turned away after the writer closed
	Failed          int  `json:"failed"`           // save failures + entries abandoned by an over-budget drain
	// BodiesFailed counts responses whose body fetch failed: stored without
	// their body (provisionally — a later complete copy is still stored).
	BodiesFailed int `json:"bodies_failed,omitempty"`
	// DrainComplete: the writer was closed and drained within its budget, so
	// every accepted entry has an outcome. False while the writer is still open.
	DrainComplete bool `json:"drain_complete"`
	// Err is the writer's close error (counts only, never record content), or
	// why capture could not start.
	Err string `json:"error,omitempty"`
}

// Clean reports whether nothing captured was lost: no failures, no refusals,
// and a finished drain. A receipt for a run without capture is trivially clean,
// so a caller that needs "capture ran AND kept everything" tests Enabled too.
//
// Named to match database.PersistenceOutcome.Clean, which asks the same
// question of the finding and record writers: the two vocabularies describe one
// concept at two layers and a reader should not have to learn both. It is also
// deliberately not Complete(), which in this tree is the ACTION that marks a
// work item done (pkg/work.Item.Complete).
func (r CaptureReceipt) Clean() bool {
	if !r.Enabled {
		return true
	}
	return r.Failed == 0 && r.Refused == 0 && r.DrainComplete
}

// Lost is the number of captured entries that did not reach the database:
// save failures and entries the writer turned away after closing. Derived in
// one place because every consumer wants the sum, not the split.
func (r CaptureReceipt) Lost() int { return r.Failed + r.Refused }

// Merge folds o into r, for a phase that sums the receipts of several runs. The
// sum is clean only when every part is; retention flags and Err keep the
// first value seen.
func (r *CaptureReceipt) Merge(o CaptureReceipt) {
	if !o.Enabled {
		return
	}
	if !r.Enabled {
		*r = o
		return
	}
	r.Accepted += o.Accepted
	r.Persisted += o.Persisted
	r.Refused += o.Refused
	r.Failed += o.Failed
	r.BodiesFailed += o.BodiesFailed
	r.DrainComplete = r.DrainComplete && o.DrainComplete
	if r.Err == "" {
		r.Err = o.Err
	}
}

// IncompleteCaptureReceipt is the receipt of a run whose writer never reported
// back — abandoned by a watchdog — so nothing it captured can be vouched for.
func IncompleteCaptureReceipt() CaptureReceipt {
	return CaptureReceipt{Enabled: true, Err: "capture abandoned before its writer drained"}
}

// newCaptureReceipt maps a writer's own account onto the public receipt.
func newCaptureReceipt(w network.Receipt, bodies, headers bool) CaptureReceipt {
	return CaptureReceipt{
		Enabled:         true,
		BodiesRetained:  bodies,
		HeadersRetained: headers,
		Accepted:        w.Accepted,
		Persisted:       w.Persisted,
		Refused:         w.Refused,
		Failed:          w.Failed,
		DrainComplete:   w.DrainComplete,
		Err:             w.Err,
	}
}

// deltaCaptureReceipt is one seed's share of a still-open shared writer: the
// difference between two of its running accounts.
//
// DrainComplete is false by construction and Err is dropped — the writer has not
// closed, so neither can be attributed to this seed. The session's own Receipt
// is the final account. Built through the same field mapping as
// newCaptureReceipt so a field added to the receipt is not silently left out of
// the per-seed form.
func deltaCaptureReceipt(before, after network.Receipt, bodies, headers bool) CaptureReceipt {
	r := newCaptureReceipt(after, bodies, headers)
	b := newCaptureReceipt(before, bodies, headers)
	r.Accepted -= b.Accepted
	r.Persisted -= b.Persisted
	r.Refused -= b.Refused
	r.Failed -= b.Failed
	r.DrainComplete = false
	r.Err = ""
	return r
}
