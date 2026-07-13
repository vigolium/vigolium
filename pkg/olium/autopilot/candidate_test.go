package autopilot

import (
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// fakeCandidateSink records saved candidates and dedups on (scan, dedup_hash)
// so tests can assert the tool's persistence + dedup behavior without a DB.
type fakeCandidateSink struct {
	saved []*database.AgentFindingCandidate
	seen  map[string]bool
}

func newFakeCandidateSink() *fakeCandidateSink {
	return &fakeCandidateSink{seen: map[string]bool{}}
}

func (f *fakeCandidateSink) SaveCandidate(_ context.Context, cand *database.AgentFindingCandidate) error {
	key := cand.AgenticScanUUID + "\x00" + cand.DedupHash
	if f.seen[key] {
		return nil // dedup: mirror ON CONFLICT DO NOTHING
	}
	f.seen[key] = true
	f.saved = append(f.saved, cand)
	return nil
}

func TestProposeCandidatePersistsAndDedups(t *testing.T) {
	sink := newFakeCandidateSink()
	section := "sec-1"
	pctx := &ProposeCandidateContext{
		Repo:            sink,
		ProjectUUID:     "proj-1",
		AgenticScanUUID: "scan-1",
		Target:          "https://test.example.com",
		SectionUUID:     &section,
	}
	tool := NewProposeCandidateTool(pctx)

	args := map[string]any{
		"title":              "IDOR on /api/orders/{id}",
		"severity":           "high",
		"description":        "order 123 readable by another tenant",
		"class":              "idor",
		"verification_notes": "replay GET /api/orders/123 as user B",
		"record_uuids":       []any{"rec-a", "rec-b"},
	}
	res, err := tool.Execute(context.Background(), args, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", res.Content)
	}
	if pctx.Count.Load() != 1 {
		t.Fatalf("count = %d, want 1", pctx.Count.Load())
	}
	if len(sink.saved) != 1 {
		t.Fatalf("saved = %d, want 1", len(sink.saved))
	}
	got := sink.saved[0]
	if got.Class != "idor" || got.Severity != "high" || got.Status != database.CandidateStatusProposed {
		t.Errorf("candidate fields wrong: class=%q sev=%q status=%q", got.Class, got.Severity, got.Status)
	}
	if got.SectionUUID != "sec-1" {
		t.Errorf("section uuid = %q, want sec-1", got.SectionUUID)
	}
	if got.Hostname != "test.example.com" {
		t.Errorf("hostname = %q, want test.example.com", got.Hostname)
	}
	if len(got.RecordUUIDs) != 2 {
		t.Errorf("record_uuids = %v, want 2", got.RecordUUIDs)
	}
	if !strings.Contains(got.Description, "Proposer verification notes:") {
		t.Errorf("verification notes not folded into description: %q", got.Description)
	}

	// Re-propose the identical candidate — deduped, count still increments (the
	// tool tracks proposal attempts) but no second row is saved.
	if _, err := tool.Execute(context.Background(), args, nil); err != nil {
		t.Fatalf("Execute (dup): %v", err)
	}
	if len(sink.saved) != 1 {
		t.Errorf("after dup: saved = %d, want 1", len(sink.saved))
	}

	// A genuinely different candidate lands.
	args2 := map[string]any{
		"title":       "Reflected XSS on /search",
		"severity":    "medium",
		"description": "q param reflected unencoded",
		"class":       "xss",
	}
	if _, err := tool.Execute(context.Background(), args2, nil); err != nil {
		t.Fatalf("Execute (xss): %v", err)
	}
	if len(sink.saved) != 2 {
		t.Errorf("after distinct: saved = %d, want 2", len(sink.saved))
	}
}

func TestProposeCandidateValidation(t *testing.T) {
	sink := newFakeCandidateSink()
	pctx := &ProposeCandidateContext{Repo: sink, AgenticScanUUID: "scan-1"}
	tool := NewProposeCandidateTool(pctx)

	// Missing severity/description.
	res, _ := tool.Execute(context.Background(), map[string]any{"title": "x"}, nil)
	if !res.IsError {
		t.Error("expected error on missing required fields")
	}
	if len(sink.saved) != 0 {
		t.Error("nothing should be saved on validation failure")
	}

	// Unknown class degrades to "other".
	res, _ = tool.Execute(context.Background(), map[string]any{
		"title": "weird bug", "severity": "low", "description": "d", "class": "banana",
	}, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content)
	}
	if sink.saved[0].Class != "other" {
		t.Errorf("class = %q, want other", sink.saved[0].Class)
	}
}

func TestProposeCandidateNoSink(t *testing.T) {
	pctx := &ProposeCandidateContext{Repo: nil}
	tool := NewProposeCandidateTool(pctx)
	res, _ := tool.Execute(context.Background(), map[string]any{
		"title": "x", "severity": "low", "description": "d",
	}, nil)
	if !res.IsError {
		t.Error("expected error result when no sink configured")
	}
}
