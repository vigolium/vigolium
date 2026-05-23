package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// saveFindingFull inserts a finding and returns its assigned ID.
func saveFindingFull(t *testing.T, repo *Repository, f *Finding) int64 {
	t.Helper()
	ctx := context.Background()
	if f.FindingHash == "" {
		f.FindingHash = uuid.NewString()
	}
	if f.ModuleID == "" {
		f.ModuleID = "mod"
	}
	if f.ModuleName == "" {
		f.ModuleName = "mod"
	}
	if f.Severity == "" {
		f.Severity = SeverityMedium
	}
	if f.Confidence == "" {
		f.Confidence = "firm"
	}
	if f.ProjectUUID == "" {
		f.ProjectUUID = DefaultProjectUUID
	}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatalf("SaveFindingDirect: %v", err)
	}
	return f.ID
}

func TestFindingGettersAndListing(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recUUID := insertRecordP(t, repo, DefaultProjectUUID, "GET", "find.example.com", "/x", 200)

	id := saveFindingFull(t, repo, &Finding{
		HTTPRecordUUIDs: []string{recUUID},
		Severity:        SeverityHigh,
		URL:             "https://find.example.com/x",
	})

	got, err := repo.GetFindingByID(ctx, id)
	if err != nil {
		t.Fatalf("GetFindingByID: %v", err)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("severity = %q", got.Severity)
	}

	byRec, err := repo.GetFindingsByRecordUUID(ctx, recUUID)
	if err != nil {
		t.Fatalf("GetFindingsByRecordUUID: %v", err)
	}
	if len(byRec) != 1 {
		t.Errorf("GetFindingsByRecordUUID = %d, want 1", len(byRec))
	}

	// GetFindingsBySeverity (project-scoped).
	saveFindingFull(t, repo, &Finding{Severity: SeverityHigh})
	highs, err := repo.GetFindingsBySeverity(ctx, DefaultProjectUUID, SeverityHigh, 10)
	if err != nil {
		t.Fatalf("GetFindingsBySeverity: %v", err)
	}
	if len(highs) != 2 {
		t.Errorf("GetFindingsBySeverity(high) = %d, want 2", len(highs))
	}

	// ListFindings with count.
	list, total, err := repo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 || len(list) != 2 {
		t.Errorf("ListFindings total=%d len=%d, want 2/2", total, len(list))
	}
}

func TestFindingStatusValidationAndUpdates(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if !IsValidFindingStatus(StatusTriaged) || IsValidFindingStatus("bogus") {
		t.Error("IsValidFindingStatus wrong")
	}
	if !IsValidFindingSeverity(SeverityCritical) || IsValidFindingSeverity("bogus") {
		t.Error("IsValidFindingSeverity wrong")
	}

	id := saveFindingFull(t, repo, &Finding{Status: StatusDraft, Severity: SeverityLow})

	// UpdateFindingStatus.
	if err := repo.UpdateFindingStatus(ctx, id, StatusTriaged); err != nil {
		t.Fatalf("UpdateFindingStatus: %v", err)
	}
	got, _ := repo.GetFindingByID(ctx, id)
	if got.Status != StatusTriaged {
		t.Errorf("status = %q, want triaged", got.Status)
	}

	// Invalid status rejected; missing row → ErrNoRows.
	if err := repo.UpdateFindingStatus(ctx, id, "bogus"); err == nil {
		t.Error("UpdateFindingStatus(bogus) should error")
	}
	if err := repo.UpdateFindingStatus(ctx, 999999, StatusFixed); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UpdateFindingStatus on missing row = %v, want sql.ErrNoRows", err)
	}

	// UpdateFindingSeverity.
	if err := repo.UpdateFindingSeverity(ctx, id, SeverityCritical); err != nil {
		t.Fatalf("UpdateFindingSeverity: %v", err)
	}
	if err := repo.UpdateFindingSeverity(ctx, id, "bogus"); err == nil {
		t.Error("UpdateFindingSeverity(bogus) should error")
	}

	// UpdateFindingTriage sets severity + description atomically.
	if err := repo.UpdateFindingTriage(ctx, id, SeverityLow, "false positive: static asset"); err != nil {
		t.Fatalf("UpdateFindingTriage: %v", err)
	}
	got, _ = repo.GetFindingByID(ctx, id)
	if got.Severity != SeverityLow || got.Description == "" {
		t.Errorf("UpdateFindingTriage wrong: sev=%q desc=%q", got.Severity, got.Description)
	}
	if err := repo.UpdateFindingTriage(ctx, id, "bogus", "x"); err == nil {
		t.Error("UpdateFindingTriage(bogus) should error")
	}
}

func TestUpdateFindingStatusByHash(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	hash := uuid.NewString()
	agUUID := uuid.NewString()
	saveFindingFull(t, repo, &Finding{
		FindingHash:     hash,
		AgenticScanUUID: agUUID,
		Status:          StatusDraft,
	})

	n, err := repo.UpdateFindingStatusByHash(ctx, agUUID, hash, StatusFalsePositive)
	if err != nil {
		t.Fatalf("UpdateFindingStatusByHash: %v", err)
	}
	if n != 1 {
		t.Errorf("rows updated = %d, want 1", n)
	}

	// Invalid args.
	if _, err := repo.UpdateFindingStatusByHash(ctx, agUUID, hash, "bogus"); err == nil {
		t.Error("invalid status should error")
	}
	if _, err := repo.UpdateFindingStatusByHash(ctx, agUUID, "", StatusFixed); err == nil {
		t.Error("empty hash should error")
	}
}

func TestDeleteFinding(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recUUID := insertRecordP(t, repo, DefaultProjectUUID, "GET", "delfind.example.com", "/x", 200)
	id := saveFindingFull(t, repo, &Finding{HTTPRecordUUIDs: []string{recUUID}})

	if err := repo.DeleteFinding(ctx, id); err != nil {
		t.Fatalf("DeleteFinding: %v", err)
	}
	if _, err := repo.GetFindingByID(ctx, id); err == nil {
		t.Error("GetFindingByID should fail after delete")
	}
}

func TestFindingCountAggregations(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	agUUID := uuid.NewString()
	saveFindingFull(t, repo, &Finding{Severity: SeverityHigh, Confidence: "firm", AgenticScanUUID: agUUID, URL: "https://x.example.com/a"})
	saveFindingFull(t, repo, &Finding{Severity: SeverityHigh, Confidence: "tentative", AgenticScanUUID: agUUID, URL: "https://x.example.com/a"})
	saveFindingFull(t, repo, &Finding{Severity: SeverityLow, Confidence: "firm", URL: "https://x.example.com/b"})

	byAgentic, err := CountFindingsByAgenticScan(ctx, db, agUUID)
	if err != nil {
		t.Fatalf("CountFindingsByAgenticScan: %v", err)
	}
	if byAgentic[SeverityHigh] != 2 {
		t.Errorf("agentic high = %d, want 2", byAgentic[SeverityHigh])
	}
	// Empty UUID short-circuits.
	if m, err := CountFindingsByAgenticScan(ctx, db, ""); err != nil || len(m) != 0 {
		t.Errorf("CountFindingsByAgenticScan(empty) = %v, %v", m, err)
	}

	byURL, err := CountFindingsByURL(ctx, db, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("CountFindingsByURL: %v", err)
	}
	if byURL["https://x.example.com/a"] != 2 || byURL["https://x.example.com/b"] != 1 {
		t.Errorf("byURL = %v", byURL)
	}

	byConf, err := CountFindingsByConfidence(ctx, db, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("CountFindingsByConfidence: %v", err)
	}
	if byConf["firm"] != 2 || byConf["tentative"] != 1 {
		t.Errorf("byConfidence = %v", byConf)
	}
}
