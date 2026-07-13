package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAgentSectionRoundTrip(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	scanUUID := uuid.NewString()
	proj := uuid.NewString()

	// Two sections, inserted out of seq order to prove ListAgentSections orders by seq.
	s2 := &AgentSection{
		UUID:            uuid.NewString(),
		AgenticScanUUID: scanUUID,
		ProjectUUID:     proj,
		Seq:             2,
		Kind:            "operator",
		Status:          SectionStatusRunning,
		Task:            "probe idor on /api/orders",
	}
	s1 := &AgentSection{
		UUID:            uuid.NewString(),
		AgenticScanUUID: scanUUID,
		ProjectUUID:     proj,
		Seq:             1,
		Kind:            "operator",
		Status:          SectionStatusRunning,
		Task:            "map surface",
	}
	if err := repo.SaveAgentSection(ctx, s2); err != nil {
		t.Fatalf("SaveAgentSection s2: %v", err)
	}
	if err := repo.SaveAgentSection(ctx, s1); err != nil {
		t.Fatalf("SaveAgentSection s1: %v", err)
	}

	// Duplicate uuid insert is a no-op (idempotent on resume).
	if err := repo.SaveAgentSection(ctx, s1); err != nil {
		t.Fatalf("SaveAgentSection s1 (dup): %v", err)
	}

	// Update s1 to completed with closing summary + turn/token counts.
	upd := &AgentSection{
		UUID:           s1.UUID,
		Status:         SectionStatusCompleted,
		ClosingSummary: "mapped 12 routes; auth is JWT",
		RotationReason: "turn cap",
		TurnCount:      40,
		InputTokens:    1000,
		OutputTokens:   500,
	}
	if err := repo.UpdateAgentSection(ctx, upd); err != nil {
		t.Fatalf("UpdateAgentSection: %v", err)
	}

	got, err := repo.ListAgentSections(ctx, scanUUID)
	if err != nil {
		t.Fatalf("ListAgentSections: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListAgentSections len = %d, want 2", len(got))
	}
	if got[0].Seq != 1 || got[1].Seq != 2 {
		t.Errorf("sections not ordered by seq: got %d,%d", got[0].Seq, got[1].Seq)
	}
	if got[0].Status != SectionStatusCompleted || got[0].ClosingSummary != "mapped 12 routes; auth is JWT" {
		t.Errorf("update not applied: status=%q summary=%q", got[0].Status, got[0].ClosingSummary)
	}
	if got[0].TurnCount != 40 || got[0].InputTokens != 1000 || got[0].OutputTokens != 500 {
		t.Errorf("counts not persisted: turns=%d in=%d out=%d", got[0].TurnCount, got[0].InputTokens, got[0].OutputTokens)
	}

	// Empty scan uuid returns nothing.
	empty, err := repo.ListAgentSections(ctx, "")
	if err != nil || len(empty) != 0 {
		t.Errorf("ListAgentSections(empty) = %v, %v", empty, err)
	}
}

func TestCandidateRoundTripAndDedup(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	scanUUID := uuid.NewString()
	proj := uuid.NewString()

	c1 := &AgentFindingCandidate{
		UUID:            uuid.NewString(),
		AgenticScanUUID: scanUUID,
		ProjectUUID:     proj,
		Title:           "IDOR on /api/orders/{id}",
		Severity:        "high",
		Description:     "order 123 readable by other tenant",
		Class:           "idor",
		Status:          CandidateStatusProposed,
		RecordUUIDs:     []string{"rec-a", "rec-b"},
		DedupHash:       "hash-1",
		URL:             "https://test.example.com/api/orders/123",
		Hostname:        "test.example.com",
	}
	inserted, err := repo.SaveCandidate(ctx, c1)
	if err != nil {
		t.Fatalf("SaveCandidate c1: %v", err)
	}
	if !inserted {
		t.Fatal("SaveCandidate c1: expected inserted=true")
	}

	// Same (scan, dedup_hash) — deduped, inserted=false.
	c1dup := *c1
	c1dup.UUID = uuid.NewString()
	inserted, err = repo.SaveCandidate(ctx, &c1dup)
	if err != nil {
		t.Fatalf("SaveCandidate c1dup: %v", err)
	}
	if inserted {
		t.Error("SaveCandidate c1dup: expected inserted=false (dedup)")
	}

	// Different hash — a new row.
	c2 := &AgentFindingCandidate{
		UUID:            uuid.NewString(),
		AgenticScanUUID: scanUUID,
		ProjectUUID:     proj,
		Title:           "XSS on /search",
		Severity:        "medium",
		Class:           "xss",
		DedupHash:       "hash-2",
	}
	if _, err := repo.SaveCandidate(ctx, c2); err != nil {
		t.Fatalf("SaveCandidate c2: %v", err)
	}

	proposed, err := repo.ListCandidates(ctx, scanUUID, CandidateStatusProposed)
	if err != nil {
		t.Fatalf("ListCandidates: %v", err)
	}
	if len(proposed) != 2 {
		t.Fatalf("proposed count = %d, want 2", len(proposed))
	}
	if len(proposed[0].RecordUUIDs) != 2 {
		t.Errorf("record_uuids not round-tripped: %v", proposed[0].RecordUUIDs)
	}

	// Verdict update: confirm c1, promote to finding id 99.
	if err := repo.UpdateCandidateStatus(ctx, c1.UUID, CandidateStatusConfirmed, "owner/non-owner compare passed", 99); err != nil {
		t.Fatalf("UpdateCandidateStatus: %v", err)
	}
	confirmed, err := repo.ListCandidates(ctx, scanUUID, CandidateStatusConfirmed)
	if err != nil {
		t.Fatalf("ListCandidates(confirmed): %v", err)
	}
	if len(confirmed) != 1 || confirmed[0].PromotedFindingID != 99 || confirmed[0].VerdictReason == "" {
		t.Errorf("verdict not applied: %+v", confirmed)
	}
	if confirmed[0].VerifiedAt.IsZero() {
		t.Error("verified_at not stamped")
	}

	// All statuses.
	all, err := repo.ListCandidates(ctx, scanUUID)
	if err != nil {
		t.Fatalf("ListCandidates(all): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("all candidates = %d, want 2", len(all))
	}
}
