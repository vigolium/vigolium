package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestSubmitVerdictToolValidation(t *testing.T) {
	sink := &verdictSink{}
	tool := newSubmitVerdictTool(sink)

	// Invalid verdict.
	res, _ := tool.Execute(context.Background(), map[string]any{"verdict": "maybe", "reason": "x"}, nil)
	if !res.IsError {
		t.Error("expected error for invalid verdict")
	}
	if sink.done() {
		t.Error("sink should not be set on invalid verdict")
	}

	// Missing reason.
	res, _ = tool.Execute(context.Background(), map[string]any{"verdict": "confirmed"}, nil)
	if !res.IsError {
		t.Error("expected error for missing reason")
	}

	// Valid — grade defaults to moderate when omitted.
	res, _ = tool.Execute(context.Background(), map[string]any{
		"verdict": "confirmed", "reason": "owner/non-owner compare passed on record rec-a",
	}, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content)
	}
	v, reason, grade, ok := sink.get()
	if !ok || v != "confirmed" || grade != "moderate" || reason == "" {
		t.Errorf("verdict not stored: v=%q reason=%q grade=%q ok=%v", v, reason, grade, ok)
	}

	// First verdict wins.
	_, _ = tool.Execute(context.Background(), map[string]any{"verdict": "rejected", "reason": "changed my mind", "evidence_grade": "weak"}, nil)
	v, _, grade, _ = sink.get()
	if v != "confirmed" || grade != "moderate" {
		t.Errorf("first verdict should win, got v=%q grade=%q", v, grade)
	}
}

func TestEvidenceGateByClass(t *testing.T) {
	cases := map[string]string{
		"idor":    "owner vs non-owner",
		"xss":     "script EXECUTION",
		"sqli":    "paired control",
		"ssrf":    "out-of-band",
		"rce":     "out-of-band",
		"auth":    "bypassed",
		"other":   "baseline",
		"unknown": "baseline",
		"":        "baseline",
	}
	for class, want := range cases {
		if got := evidenceGate(class); !strings.Contains(got, want) {
			t.Errorf("evidenceGate(%q) missing %q: %s", class, want, got)
		}
	}
}

func TestPromotedFindingHashDistinctForShadow(t *testing.T) {
	cand := &database.AgentFindingCandidate{
		Title: "t", Severity: "high", URL: "https://test.example.com", Description: "d", DedupHash: "base-hash",
	}
	enforced := promotedFindingHash(cand, config.AutopilotModeEnforced)
	shadow := promotedFindingHash(cand, config.AutopilotModeShadow)
	if enforced != "base-hash" {
		t.Errorf("enforced hash = %q, want base-hash (reuse candidate dedup)", enforced)
	}
	if shadow == enforced {
		t.Error("shadow hash must differ from the direct finding hash so both coexist")
	}

	// Empty dedup hash falls back to a computed content hash (non-empty).
	cand2 := &database.AgentFindingCandidate{Title: "t2", Severity: "low", URL: "u", Description: "d"}
	if h := promotedFindingHash(cand2, config.AutopilotModeEnforced); h == "" {
		t.Error("expected a computed hash when candidate has no dedup hash")
	}
}

func TestPromoteCandidateWritesFinding(t *testing.T) {
	repo := newAuditTestRepo(t)
	ctx := context.Background()
	proj := uuid.NewString()
	scan := uuid.NewString()

	cand := &database.AgentFindingCandidate{
		UUID: uuid.NewString(), AgenticScanUUID: scan, ProjectUUID: proj,
		Title: "IDOR on /api/orders", Severity: "high", Description: "cross-tenant read",
		Class: "idor", Status: database.CandidateStatusProposed, DedupHash: "dh-1",
		URL: "https://test.example.com/api/orders/1", Hostname: "test.example.com",
		RecordUUIDs: []string{"rec-a"},
	}
	if _, err := repo.SaveCandidate(ctx, cand); err != nil {
		t.Fatalf("SaveCandidate: %v", err)
	}

	cfg := VerifyCandidatesConfig{
		Repo: repo, ProjectUUID: proj, ScanUUID: scan, AgenticScanUUID: scan,
		Mode: config.AutopilotModeEnforced,
	}
	v := candidateVerdict{verdict: database.CandidateStatusConfirmed, reason: "owner/non-owner compare passed", grade: "strong"}
	id, err := promoteCandidate(ctx, cfg, cand, v, config.AutopilotModeEnforced)
	if err != nil {
		t.Fatalf("promoteCandidate: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero finding id")
	}

	f, err := repo.GetFindingByID(ctx, id)
	if err != nil {
		t.Fatalf("GetFindingByID: %v", err)
	}
	if f.Severity != "high" || f.FindingSource != "autopilot-verified" || f.FindingHash != "dh-1" {
		t.Errorf("promoted finding wrong: sev=%q src=%q hash=%q", f.Severity, f.FindingSource, f.FindingHash)
	}
	if f.EvidenceGrade != "strong" {
		t.Errorf("evidence grade = %q, want strong", f.EvidenceGrade)
	}
	if !strings.Contains(f.Description, "Verifier verdict:") {
		t.Errorf("verdict reason not folded into description: %q", f.Description)
	}
}
