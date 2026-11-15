package database

import (
	"context"
	"testing"
)

// A severity delete removes findings only, and both delete modes report every
// table they touch; the dry run's counts equal the real run's.
func TestDeleteByTableCountsAndSeverityKeepsRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	rec := insertRecordP(t, repo, DefaultProjectUUID, "GET", "sev.example.com", "/a", 200)
	saveFindingFull(t, repo, &Finding{HTTPRecordUUIDs: []string{rec}, ModuleName: "high-one", Severity: SeverityHigh})
	saveFindingFull(t, repo, &Finding{HTTPRecordUUIDs: []string{rec}, ModuleName: "critical-one", Severity: SeverityCritical})

	del := NewDeleteBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, Severity: []string{"high"}})
	dry, err := del.DeleteFindingsByTable(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if dry["findings"] != 1 || dry["finding_records"] != 1 || dry["http_records"] != 0 {
		t.Fatalf("dry-run counts = %v", dry)
	}
	if n, _ := db.NewSelect().Model((*Finding)(nil)).Count(ctx); n != 2 {
		t.Fatalf("dry run deleted findings: %d left", n)
	}
	real, err := del.DeleteFindingsByTable(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if real["findings"] != dry["findings"] || real["finding_records"] != dry["finding_records"] {
		t.Fatalf("real %v != dry %v", real, dry)
	}
	if n, _ := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx); n != 1 {
		t.Fatalf("records = %d, want 1 (severity delete must keep records)", n)
	}

	// Deleting the record takes the critical finding (its only evidence) too,
	// and says so per table.
	rdel := NewDeleteBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, HostPattern: "sev.example.com"})
	dry, err = rdel.DeleteRecordsByTable(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if dry["http_records"] != 1 || dry["findings"] != 1 || dry["finding_records"] != 1 {
		t.Fatalf("records dry-run counts = %v", dry)
	}
	real, err = rdel.DeleteRecordsByTable(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if real["http_records"] != 1 || real["findings"] != 1 {
		t.Fatalf("records real counts = %v", real)
	}
}
