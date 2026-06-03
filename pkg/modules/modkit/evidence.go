package modkit

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// MaxEvidencePairs caps how many request/response pairs a single finding carries
// in AdditionalEvidence at emit time. It matches the dedup-merge cap in
// pkg/database so a high-round differential module (boolean-blind SQLi, race
// interference) can't emit an unbounded finding. The first MaxEvidencePairs pairs
// win — modules record the most informative context first (baseline, then
// confirmation rounds), so the tail that gets dropped is the least interesting.
const MaxEvidencePairs = 10

// EvidenceCollector accumulates the supporting request/response pairs a
// differential module sends while proving a finding — the baseline it compared
// against, and any confirmation/refetch rounds — so they can be attached to the
// finding's AdditionalEvidence instead of being discarded. The primary attack
// pair (the proof) stays in the finding's Request/Response fields; the collector
// holds the surrounding context that explains *why* it's a finding.
//
// The zero value is ready to use. All methods are nil-safe, so a module can pass
// a possibly-nil *EvidenceCollector into shared helpers (e.g. reconfirm) without
// guarding each call site.
type EvidenceCollector struct {
	entries []string
}

// NewEvidenceCollector returns a ready-to-use collector. Equivalent to
// &EvidenceCollector{}; provided for call-site readability.
func NewEvidenceCollector() *EvidenceCollector {
	return &EvidenceCollector{}
}

// Add records one labeled request/response pair. The label (e.g. "baseline",
// "attack", "confirm round 2") becomes a "# [label]" marker line so reviewers and
// the UI's evidence tabs can tell the pairs apart. Empty pairs are ignored, and
// additions past MaxEvidencePairs are dropped. Safe to call on a nil collector
// (no-op), so reconfirm and other shared helpers can record unconditionally.
func (c *EvidenceCollector) Add(label, request, response string) {
	if c == nil || len(c.entries) >= MaxEvidencePairs {
		return
	}
	entry := output.BuildEvidence(label, request, response)
	if entry == "" {
		return
	}
	c.entries = append(c.entries, entry)
}

// Entries returns a copy of the collected evidence entries for assignment to a
// ResultEvent's AdditionalEvidence. Returns nil (not an empty slice) when nothing
// was collected, so a finding without extra context stays unset. Safe on a nil
// collector.
func (c *EvidenceCollector) Entries() []string {
	if c == nil || len(c.entries) == 0 {
		return nil
	}
	out := make([]string, len(c.entries))
	copy(out, c.entries)
	return out
}

// Len reports how many pairs have been collected so far. Safe on a nil collector.
func (c *EvidenceCollector) Len() int {
	if c == nil {
		return 0
	}
	return len(c.entries)
}

// CtxRequestRaw renders ctx's request as a raw string for evidence capture,
// returning "" when the request is absent. Pair with CtxResponseRaw to record the
// original (clean) request/response a module compared its probe against.
func CtxRequestRaw(ctx *httpmsg.HttpRequestResponse) string {
	if ctx == nil || ctx.Request() == nil {
		return ""
	}
	return string(ctx.Request().Raw())
}

// CtxResponseRaw renders ctx's response as a full raw response string for evidence
// capture, returning "" when no response is present.
func CtxResponseRaw(ctx *httpmsg.HttpRequestResponse) string {
	if ctx == nil || ctx.Response() == nil {
		return ""
	}
	return string(ctx.Response().Raw())
}
