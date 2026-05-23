package database

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newScan(t *testing.T, repo *Repository, projectUUID string) *Scan {
	t.Helper()
	ctx := context.Background()
	s := &Scan{
		UUID:        uuid.NewString(),
		ProjectUUID: projectUUID,
		Name:        "test-scan",
		Status:      "running",
		Target:      "https://target.example.com",
	}
	if err := repo.CreateScan(ctx, s); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	return s
}

func TestScanUpdatePaths(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	s := newScan(t, repo, DefaultProjectUUID)

	// UpdateScan (full).
	s.Name = "renamed"
	s.Description = "full update"
	if err := repo.UpdateScan(ctx, s); err != nil {
		t.Fatalf("UpdateScan: %v", err)
	}

	// UpdateScanPartial keeps untouched fields.
	if err := repo.UpdateScanPartial(ctx, &Scan{UUID: s.UUID, Status: "paused"}); err != nil {
		t.Fatalf("UpdateScanPartial: %v", err)
	}
	got, _ := repo.GetScanByUUID(ctx, s.UUID)
	if got.Status != "paused" {
		t.Errorf("status = %q, want paused", got.Status)
	}
	if got.Name != "renamed" {
		t.Errorf("UpdateScanPartial clobbered name: %q", got.Name)
	}

	// UpdateScanStorageURL.
	if err := repo.UpdateScanStorageURL(ctx, s.UUID, "gs://bucket/scan"); err != nil {
		t.Fatalf("UpdateScanStorageURL: %v", err)
	}
	got, _ = repo.GetScanByUUID(ctx, s.UUID)
	if got.StorageURL != "gs://bucket/scan" {
		t.Errorf("storage_url = %q", got.StorageURL)
	}

	// Error paths.
	if err := repo.UpdateScan(ctx, nil); err == nil {
		t.Error("UpdateScan(nil) should error")
	}
	if err := repo.UpdateScanPartial(ctx, &Scan{}); err == nil {
		t.Error("UpdateScanPartial without UUID should error")
	}
}

func TestCreateScanProjectMismatch(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	id := uuid.NewString()
	if err := repo.CreateScan(ctx, &Scan{UUID: id, ProjectUUID: "proj-x", Status: "running"}); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	// Re-create with same UUID under a different project → mismatch error.
	err := repo.CreateScan(ctx, &Scan{UUID: id, ProjectUUID: "proj-y", Status: "running"})
	if err == nil {
		t.Fatal("expected ErrScanProjectMismatch")
	}
	// Same project re-create is a no-op.
	if err := repo.CreateScan(ctx, &Scan{UUID: id, ProjectUUID: "proj-x", Status: "running"}); err != nil {
		t.Errorf("re-create under same project: %v", err)
	}
	if err := repo.CreateScan(ctx, nil); err == nil {
		t.Error("CreateScan(nil) should error")
	}
}

func TestCompleteScanAndStats(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	s := newScan(t, repo, DefaultProjectUUID)

	// Two findings linked to the scan.
	for _, sev := range []string{SeverityHigh, SeverityCritical} {
		f := &Finding{
			ProjectUUID: DefaultProjectUUID,
			ScanUUID:    s.UUID,
			ModuleID:    "m",
			ModuleName:  "m",
			Severity:    sev,
			Confidence:  "firm",
			FindingHash: uuid.NewString(),
		}
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatalf("SaveFindingDirect: %v", err)
		}
	}

	// RefreshScanStats populates severity counts mid-scan.
	if err := repo.RefreshScanStats(ctx, s.UUID); err != nil {
		t.Fatalf("RefreshScanStats: %v", err)
	}
	got, _ := repo.GetScanByUUID(ctx, s.UUID)
	if got.HighCount != 1 || got.CriticalCount != 1 {
		t.Errorf("after refresh: high=%d critical=%d", got.HighCount, got.CriticalCount)
	}

	// CompleteScan marks completed and sets finished_at.
	if err := repo.CompleteScan(ctx, s.UUID, ""); err != nil {
		t.Fatalf("CompleteScan: %v", err)
	}
	got, _ = repo.GetScanByUUID(ctx, s.UUID)
	if got.Status != "completed" {
		t.Errorf("status = %q, want completed", got.Status)
	}
	if got.TotalFindings != 2 {
		t.Errorf("total findings = %d, want 2", got.TotalFindings)
	}

	// CompleteScan with error message → failed.
	s2 := newScan(t, repo, DefaultProjectUUID)
	if err := repo.CompleteScan(ctx, s2.UUID, "boom"); err != nil {
		t.Fatalf("CompleteScan(failed): %v", err)
	}
	got2, _ := repo.GetScanByUUID(ctx, s2.UUID)
	if got2.Status != "failed" || got2.ErrorMessage != "boom" {
		t.Errorf("failed scan: status=%q err=%q", got2.Status, got2.ErrorMessage)
	}
}

func TestListScansAndDelete(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	proj := uuid.NewString()
	for i := 0; i < 3; i++ {
		newScan(t, repo, proj)
	}
	// A scan in a different project must not leak.
	newScan(t, repo, uuid.NewString())

	scans, total, err := repo.ListScans(ctx, proj, 10, 0)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if total != 3 || len(scans) != 3 {
		t.Errorf("ListScans total=%d len=%d, want 3/3", total, len(scans))
	}

	if err := repo.DeleteScan(ctx, scans[0].UUID); err != nil {
		t.Fatalf("DeleteScan: %v", err)
	}
	_, total, _ = repo.ListScans(ctx, proj, 10, 0)
	if total != 2 {
		t.Errorf("after delete total=%d, want 2", total)
	}
}

func TestScanCursorAndCounting(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	s := newScan(t, repo, DefaultProjectUUID)

	// Seed records so cursor counting has data.
	for i := 0; i < 3; i++ {
		insertRecordP(t, repo, DefaultProjectUUID, "GET", "cursor.example.com", "/r"+string(rune('a'+i)), 200)
	}

	// IncrementProcessedCount.
	if err := repo.IncrementProcessedCount(ctx, s.UUID, 5); err != nil {
		t.Fatalf("IncrementProcessedCount: %v", err)
	}
	if err := repo.IncrementProcessedCount(ctx, s.UUID, 0); err != nil {
		t.Errorf("IncrementProcessedCount(0): %v", err)
	}

	// AdvanceScanCursor / AdvanceScanCursorBy.
	if err := repo.AdvanceScanCursor(ctx, s.UUID, time.Now(), "rec-uuid"); err != nil {
		t.Fatalf("AdvanceScanCursor: %v", err)
	}
	if err := repo.AdvanceScanCursorBy(ctx, s.UUID, time.Now(), "rec-uuid-2", 3); err != nil {
		t.Fatalf("AdvanceScanCursorBy: %v", err)
	}
	got, _ := repo.GetScanByUUID(ctx, s.UUID)
	if got.ProcessedCount != 9 { // 5 + 1 + 3
		t.Errorf("processed_count = %d, want 9", got.ProcessedCount)
	}

	// ResetScanCursor clears it.
	if err := repo.ResetScanCursor(ctx, s.UUID); err != nil {
		t.Fatalf("ResetScanCursor: %v", err)
	}
	got, _ = repo.GetScanByUUID(ctx, s.UUID)
	if got.CursorUUID != "" {
		t.Errorf("cursor not reset: %q", got.CursorUUID)
	}

	// Counting after a zero cursor counts all records.
	count, err := repo.CountRecordsAfterCursor(ctx, time.Time{}, "")
	if err != nil {
		t.Fatalf("CountRecordsAfterCursor: %v", err)
	}
	if count != 3 {
		t.Errorf("CountRecordsAfterCursor = %d, want 3", count)
	}

	// By source.
	bySource, err := repo.CountRecordsAfterCursorBySource(ctx, time.Time{}, "", []string{"test"}, nil)
	if err != nil {
		t.Fatalf("CountRecordsAfterCursorBySource: %v", err)
	}
	if bySource != 3 {
		t.Errorf("CountRecordsAfterCursorBySource = %d, want 3", bySource)
	}
}

func TestPauseResumeScan(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	s := newScan(t, repo, DefaultProjectUUID)
	if err := repo.PauseScan(ctx, s.UUID); err != nil {
		t.Fatalf("PauseScan: %v", err)
	}
	got, _ := repo.GetScanByUUID(ctx, s.UUID)
	if got.Status != "paused" {
		t.Errorf("status = %q, want paused", got.Status)
	}
	if err := repo.ResumeScan(ctx, s.UUID); err != nil {
		t.Fatalf("ResumeScan: %v", err)
	}
	got, _ = repo.GetScanByUUID(ctx, s.UUID)
	if got.Status != "running" {
		t.Errorf("status = %q, want running", got.Status)
	}
}

func TestCreateScanWithCursorIncremental(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// A prior completed scan with a cursor for modules "xss".
	prev := &Scan{
		UUID:        uuid.NewString(),
		ProjectUUID: DefaultProjectUUID,
		Status:      "completed",
		Modules:     "xss",
		CursorAt:    time.Now().Add(-time.Hour),
		CursorUUID:  "prev-cursor",
		FinishedAt:  time.Now().Add(-time.Hour),
	}
	if err := repo.CreateScanWithCursor(ctx, prev); err != nil {
		t.Fatalf("CreateScanWithCursor(prev): %v", err)
	}

	// New incremental scan copies the cursor.
	inc := &Scan{
		UUID:        uuid.NewString(),
		ProjectUUID: DefaultProjectUUID,
		Status:      "running",
		Modules:     "xss",
		ScanMode:    "incremental",
	}
	if err := repo.CreateScanWithCursor(ctx, inc); err != nil {
		t.Fatalf("CreateScanWithCursor(inc): %v", err)
	}
	got, _ := repo.GetScanByUUID(ctx, inc.UUID)
	if got.StartCursorUUID != "prev-cursor" {
		t.Errorf("incremental cursor not copied: %q", got.StartCursorUUID)
	}

	if err := repo.CreateScanWithCursor(ctx, nil); err == nil {
		t.Error("CreateScanWithCursor(nil) should error")
	}
}

func TestScanLogs(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	s := newScan(t, repo, DefaultProjectUUID)

	if err := repo.CreateScanLog(ctx, &ScanLog{
		ScanUUID: s.UUID, Level: "info", Phase: "discovery", Message: "started",
	}); err != nil {
		t.Fatalf("CreateScanLog: %v", err)
	}
	if err := repo.CreateScanLogBatch(ctx, []*ScanLog{
		{ScanUUID: s.UUID, Level: "warn", Phase: "dynamic-assessment", Message: "slow"},
		{ScanUUID: s.UUID, Level: "error", Phase: "dynamic-assessment", Message: "fail"},
	}); err != nil {
		t.Fatalf("CreateScanLogBatch: %v", err)
	}

	logs, total, err := repo.ListScanLogs(ctx, s.UUID, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListScanLogs: %v", err)
	}
	if total != 3 || len(logs) != 3 {
		t.Errorf("ListScanLogs total=%d len=%d, want 3/3", total, len(logs))
	}

	// Filter by level + phase.
	filtered, total, err := repo.ListScanLogs(ctx, s.UUID, "warn", "dynamic-assessment", 10, 0)
	if err != nil {
		t.Fatalf("ListScanLogs(filtered): %v", err)
	}
	if total != 1 || len(filtered) != 1 {
		t.Errorf("filtered logs total=%d len=%d, want 1/1", total, len(filtered))
	}

	// Nil/empty inputs are no-ops.
	if err := repo.CreateScanLog(ctx, nil); err == nil {
		t.Error("CreateScanLog(nil) should error")
	}
	if err := repo.CreateScanLogBatch(ctx, nil); err != nil {
		t.Errorf("CreateScanLogBatch(nil): %v", err)
	}
}

func TestLoadEnabledScopes(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	proj := uuid.NewString()
	// Insert two scopes, one disabled. The enabled column has DEFAULT TRUE and a
	// false bool is the Go zero value, so bun omits it and the default fires — we
	// must clear it with an explicit column UPDATE after insert.
	scopes := []*Scope{
		{ProjectUUID: proj, Name: "inc", RuleType: "include", Priority: 10, Enabled: true},
		{ProjectUUID: proj, Name: "off", RuleType: "exclude", Priority: 5},
	}
	if _, err := db.NewInsert().Model(&scopes).Exec(ctx); err != nil {
		t.Fatalf("insert scopes: %v", err)
	}
	if _, err := db.NewUpdate().Model((*Scope)(nil)).
		Set("enabled = ?", false).
		Where("project_uuid = ?", proj).
		Where("name = ?", "off").
		Exec(ctx); err != nil {
		t.Fatalf("disable scope: %v", err)
	}

	loaded, err := repo.LoadEnabledScopes(ctx, proj)
	if err != nil {
		t.Fatalf("LoadEnabledScopes: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Name != "inc" {
		t.Errorf("LoadEnabledScopes = %v, want only the enabled one", loaded)
	}
}
