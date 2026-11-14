package database

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestObservedInScan_DedupKeepsReDetectionInGate: a timing
// module puts the measured delay in its description, so a re-detection in scan
// S2 hashes differently from S1's row. The URL dedup merges the two and keeps
// the oldest row; the S2 --fail-on gate must still count it.
func TestObservedInScan_DedupKeepsReDetectionInGate(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	ev1 := makeFindingEvent("command-injection-timing", "/run?cmd=x", severity.High)
	ev1.Info.Description = "Response delayed 5012ms after sleep payload"
	if err := repo.SaveFinding(ctx, ev1, nil, "S1", DefaultProjectUUID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // created_at has second resolution on SQLite
	ev2 := makeFindingEvent("command-injection-timing", "/run?cmd=x", severity.High)
	ev2.Info.Description = "Response delayed 5023ms after sleep payload"
	if err := repo.SaveFinding(ctx, ev2, nil, "S2", DefaultProjectUUID); err != nil {
		t.Fatal(err)
	}
	if deleted, _, err := repo.DeduplicateFindings(ctx, DefaultProjectUUID); err != nil || deleted != 1 {
		t.Fatalf("DeduplicateFindings deleted=%d err=%v, want 1 merged", deleted, err)
	}

	for _, f := range []QueryFilters{
		{ProjectUUID: DefaultProjectUUID, ObservedInScan: "S2", Severity: []string{"high"}},
		{ProjectUUID: DefaultProjectUUID, ScanUUID: "S2", Severity: []string{"high"}},
		{ProjectUUID: DefaultProjectUUID, ObservedInScan: "S1", Severity: []string{"high"}},
	} {
		n, err := NewFindingsQueryBuilder(db, f).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("count(%+v) = %d, want 1", f, n)
		}
	}
	if sc := repo.aggregateScanFindings(ctx, "S1"); sc.Total != 1 {
		t.Errorf("S1 summary total = %d, want 1 (S1 observed it too)", sc.Total)
	}
}
