package database

import (
	"context"
	"testing"
	"time"
)

// A scan-on-receive row inherits the newest earlier one's cursor whatever its
// status; any other incremental scan still needs a completed predecessor.
func TestCreateScanWithCursorScanOnReceiveInheritsAnyStatus(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	cursor := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	prev := &Scan{UUID: "sor-old", ProjectUUID: DefaultProjectUUID, Status: "cancelled", Modules: "all",
		ScanSource: ScanSourceScanOnReceive, ScanMode: "incremental", StartedAt: cursor, CursorAt: cursor, CursorUUID: "rec-9"}
	if err := repo.CreateScan(ctx, prev); err != nil {
		t.Fatal(err)
	}
	next := &Scan{UUID: "sor-new", ProjectUUID: DefaultProjectUUID, Status: "running", Modules: "all",
		ScanSource: ScanSourceScanOnReceive, ScanMode: "incremental", StartedAt: time.Now()}
	if err := repo.CreateScanWithCursor(ctx, next); err != nil {
		t.Fatal(err)
	}
	if !next.CursorAt.Equal(cursor) || next.CursorUUID != "rec-9" {
		t.Fatalf("scan-on-receive cursor = %v %q, want the cancelled predecessor's", next.CursorAt, next.CursorUUID)
	}
	got, err := repo.LatestScanOnReceiveScan(ctx, DefaultProjectUUID)
	if err != nil || got == nil || got.UUID != "sor-new" {
		t.Fatalf("LatestScanOnReceiveScan = %+v, %v", got, err)
	}

	cli := &Scan{UUID: "cli-new", ProjectUUID: DefaultProjectUUID, Status: "running", Modules: "all",
		ScanSource: "cli", ScanMode: "incremental", StartedAt: time.Now()}
	if err := repo.CreateScanWithCursor(ctx, cli); err != nil {
		t.Fatal(err)
	}
	if !cli.CursorAt.IsZero() {
		t.Fatalf("a non-scan-on-receive incremental scan inherited a cancelled run's cursor: %v", cli.CursorAt)
	}
}
