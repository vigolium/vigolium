package database

import (
	"context"
	"testing"
	"time"
)

// TestDBInputSource_ServesSameSecondSmallerUUID is MISS-34: on SQLite the
// cursor compares one-second created_at values and tie-breaks on a random
// UUID, so a record committed in the cursor's second with a smaller UUID used
// to be skipped forever. The polling source re-reads a short window behind its
// cursor and serves it exactly once, without moving the durable cursor back.
func TestDBInputSource_ServesSameSecondSmallerUUID(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)
	const second = "2026-01-02 03:04:05"

	pin := func(uuid, newUUID string) {
		if _, err := db.ExecContext(ctx, "UPDATE http_records SET uuid = ?, created_at = ? WHERE uuid = ?", newUUID, second, uuid); err != nil {
			t.Fatal(err)
		}
	}
	first := insertTestRecordsWithHost(t, repo, "first.example.com", 1)[0]
	pin(first, "ffffffff-0000-0000-0000-000000000001")

	src := NewDBInputSource(db, repo, scanUUID, 10*time.Millisecond)
	next := func() string {
		c, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		item, err := src.Next(c)
		if err != nil {
			return ""
		}
		item.Complete()
		return item.RecordUUID
	}
	if got := next(); got != "ffffffff-0000-0000-0000-000000000001" {
		t.Fatalf("first = %q", got)
	}

	late := insertTestRecordsWithHost(t, repo, "late.example.com", 1)[0]
	pin(late, "00000000-0000-0000-0000-000000000002")
	if got := next(); got != "00000000-0000-0000-0000-000000000002" {
		t.Fatalf("late same-second record not served: got %q", got)
	}
	if got := next(); got != "" {
		t.Fatalf("a record was served twice: %q", got)
	}

	scan, err := repo.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		t.Fatal(err)
	}
	if scan.CursorUUID != "ffffffff-0000-0000-0000-000000000001" || scan.ProcessedCount != 2 {
		t.Fatalf("durable cursor = %q processed=%d, want the furthest key and 2", scan.CursorUUID, scan.ProcessedCount)
	}
}
