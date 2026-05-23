package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestDeleteBuilder_DeleteRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordP(t, repo, DefaultProjectUUID, "GET", "rmrec.example.com", "/a", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "rmrec.example.com", "/b", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "keep.example.com", "/c", 200)

	filters := QueryFilters{ProjectUUID: DefaultProjectUUID, HostPattern: "rmrec.example.com"}
	dbld := NewDeleteBuilder(db, filters)

	// Dry run returns the matched count without deleting.
	n, err := dbld.DeleteRecords(ctx, true)
	if err != nil {
		t.Fatalf("DeleteRecords(dryRun): %v", err)
	}
	if n != 2 {
		t.Errorf("dry run count = %d, want 2", n)
	}

	// Real delete.
	n, err = dbld.DeleteRecords(ctx, false)
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}
	remaining, _ := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if remaining != 1 {
		t.Errorf("remaining records = %d, want 1", remaining)
	}
}

func TestDeleteBuilder_DeleteFindingsAndOrphans(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// A finding linked to an existing record (not orphan).
	recUUID := insertRecordP(t, repo, DefaultProjectUUID, "GET", "fdel.example.com", "/x", 200)
	saveFindingFull(t, repo, &Finding{HTTPRecordUUIDs: []string{recUUID}, ModuleName: "linked", Severity: SeverityHigh})

	// An orphan finding referencing a non-existent record.
	saveFindingFull(t, repo, &Finding{HTTPRecordUUIDs: []string{"ghost-uuid"}, ModuleName: "orphan", Severity: SeverityLow})

	dbld := NewDeleteBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID})

	// DeleteOrphans dry run counts orphans (the one with no live junction row).
	orphans, err := dbld.DeleteOrphans(ctx, true)
	if err != nil {
		t.Fatalf("DeleteOrphans(dryRun): %v", err)
	}
	// Exactly one orphan was seeded (the "ghost-uuid" finding); the linked
	// finding must NOT be counted. == 1 catches a join regression that would
	// over-count (e.g. treating the linked finding as an orphan too).
	if orphans != 1 {
		t.Errorf("orphan dry run = %d, want exactly 1", orphans)
	}
	if _, err := dbld.DeleteOrphans(ctx, false); err != nil {
		t.Fatalf("DeleteOrphans: %v", err)
	}

	// DeleteFindings by module name filter.
	dbld2 := NewDeleteBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ModuleName: "linked"})
	dn, err := dbld2.DeleteFindings(ctx, true)
	if err != nil {
		t.Fatalf("DeleteFindings(dryRun): %v", err)
	}
	if dn != 1 {
		t.Errorf("DeleteFindings dry run = %d, want 1", dn)
	}
	if _, err := dbld2.DeleteFindings(ctx, false); err != nil {
		t.Fatalf("DeleteFindings: %v", err)
	}
}

func TestDeleteBuilder_DeleteTableAndAll(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordP(t, repo, DefaultProjectUUID, "GET", "tbl.example.com", "/a", 200)
	saveFindingFull(t, repo, &Finding{ModuleName: "m", Severity: SeverityHigh})

	dbld := NewDeleteBuilder(db, QueryFilters{})

	// DeleteTable rejects unknown tables.
	if _, err := dbld.DeleteTable(ctx, "not_a_table", false); err == nil {
		t.Error("DeleteTable(unknown) should error")
	}

	// DeleteTable on findings (cascades finding_records first).
	cnt, err := dbld.DeleteTable(ctx, "findings", true)
	if err != nil {
		t.Fatalf("DeleteTable(dryRun): %v", err)
	}
	if cnt != 1 {
		t.Errorf("findings dry count = %d, want 1", cnt)
	}
	if _, err := dbld.DeleteTable(ctx, "findings", false); err != nil {
		t.Fatalf("DeleteTable: %v", err)
	}

	// DeleteAllTables dry run returns per-table counts.
	counts, err := dbld.DeleteAllTables(ctx, true)
	if err != nil {
		t.Fatalf("DeleteAllTables(dryRun): %v", err)
	}
	if counts["http_records"] != 1 {
		t.Errorf("http_records count = %d, want 1", counts["http_records"])
	}
	if _, err := dbld.DeleteAllTables(ctx, false); err != nil {
		t.Fatalf("DeleteAllTables: %v", err)
	}
	left, _ := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if left != 0 {
		t.Errorf("after DeleteAllTables records = %d, want 0", left)
	}

	// AllTablesDeleteOrder is exported.
	if len(AllTablesDeleteOrder()) == 0 {
		t.Error("AllTablesDeleteOrder() empty")
	}
}

func TestDeleteBuilder_NoMatch(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	dbld := NewDeleteBuilder(db, QueryFilters{ProjectUUID: uuid.NewString()})
	n, err := dbld.DeleteRecords(ctx, false)
	if err != nil || n != 0 {
		t.Errorf("DeleteRecords(no match) = %d, %v", n, err)
	}
	fn, err := dbld.DeleteFindings(ctx, false)
	if err != nil || fn != 0 {
		t.Errorf("DeleteFindings(no match) = %d, %v", fn, err)
	}
}
