package work

import "github.com/vigolium/vigolium/pkg/httpmsg"

// WorkItem represents a unit of work with lifecycle management.
// It wraps an HTTP request/response pair with an optional completion callback.
type WorkItem struct {
	Request       *httpmsg.HttpRequestResponse
	EnableModules []string // Per-task module selection (empty = use all)
	RecordUUID    string   // Pre-existing DB record UUID (skip store, use for findings)

	// StaticMeta marks a static-file request kept by the executor's
	// object-storage carve-out: it is fetched with HEAD and recorded as a
	// metadata-only http_record (body stripped) so the CDN traversal modules can
	// probe storage-fronted static assets without storing their (binary) bodies.
	StaticMeta bool

	// Target is the input line this item came from, as it appears in
	// Options.Targets: normalized to an absolute URL, so a submitted
	// "dns.google" reads as "http://dns.google" (and, on the probe path, as
	// whatever scheme resolution settled on). Empty for items a source
	// synthesized rather than received — a crawl discovery, an ingested
	// record — which have no submitted line to name.
	//
	// Normalized rather than verbatim because normalization happens in the CLI
	// before any source sees the list. Recovering the operator's exact
	// keystrokes would mean deduping on a normalized key while storing the raw
	// line, which is a change to the target pipeline rather than to this field.
	//
	// It is carried on the item rather than re-derived from the request
	// because normalization has already happened by then, and because a
	// followed redirect moves the request off the submitted URL entirely: the
	// stored record's hostname is the LAST hop's, so without this a consumer
	// cannot tell which of its 5,000 lines produced the row.
	Target string

	// Remarks are stamped on the record the executor stores for this item, on
	// a new row only (a dedup hit keeps its own). The executor appends them
	// itself — a block page kept under KeepBlocked carries "blocked:<reason>" so
	// a later read can tell it from the application's own answer.
	Remarks []string

	// Coverage, when set, is this record's stored progress in the coverage
	// ledger (ECON-4): the executor skips the modules whose bit is set and the
	// passive stage when it already ran. nil = nothing recorded yet.
	Coverage *Coverage

	onComplete func()
}

// Coverage is a record's coverage-ledger state (see database.ScanRecordProgress).
type Coverage struct {
	TierDone    int
	PassiveDone bool
	DoneBits    []byte
}

// ModuleDone reports whether the module at ordinal finished on this record.
func (c *Coverage) ModuleDone(ordinal int) bool {
	if c == nil || ordinal < 0 {
		return false
	}
	i := ordinal / 8
	return i < len(c.DoneBits) && c.DoneBits[i]&(1<<uint(ordinal%8)) != 0
}

// NewWithModules creates a WorkItem with EnableModules but no callback.
// Use this for file/stdin/target sources when module filtering is needed.
func NewWithModules(request *httpmsg.HttpRequestResponse, enableModules []string) *WorkItem {
	return &WorkItem{
		Request:       request,
		EnableModules: enableModules,
	}
}

// NewWithCallback creates a WorkItem with completion callback.
// Use this for queue sources where tasks need to be acked after processing.
func NewWithCallback(request *httpmsg.HttpRequestResponse, enableModules []string, onComplete func()) *WorkItem {
	return &WorkItem{
		Request:       request,
		EnableModules: enableModules,
		onComplete:    onComplete,
	}
}

// Complete signals the work item has been processed.
// Safe to call even if onComplete is nil.
func (w *WorkItem) Complete() {
	if w.onComplete != nil {
		w.onComplete()
	}
}
