package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestAttributeScanToAgenticScan verifies a tool-launched native scan and only
// its own findings get stamped with the parent agentic-scan UUID, so they
// surface under `finding --agentic-scan <parent>` (which filters on
// finding.agentic_scan_uuid directly).
func TestAttributeScanToAgenticScan(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	proj := uuid.NewString()
	agenticUUID := uuid.NewString()
	scanUUID := uuid.NewString()
	otherScan := uuid.NewString()

	if err := repo.CreateScan(ctx, &Scan{
		UUID:        scanUUID,
		ProjectUUID: proj,
		Name:        "child",
		Status:      "completed",
	}); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	fid1 := saveFindingFull(t, repo, &Finding{ProjectUUID: proj, ScanUUID: scanUUID})
	fid2 := saveFindingFull(t, repo, &Finding{ProjectUUID: proj, ScanUUID: scanUUID})
	fidOther := saveFindingFull(t, repo, &Finding{ProjectUUID: proj, ScanUUID: otherScan})

	if err := repo.AttributeScanToAgenticScan(ctx, scanUUID, agenticUUID); err != nil {
		t.Fatalf("AttributeScanToAgenticScan: %v", err)
	}

	// Scan row is stamped.
	scan, err := repo.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		t.Fatalf("GetScanByUUID: %v", err)
	}
	if scan.AgenticScanUUID != agenticUUID {
		t.Errorf("scan.AgenticScanUUID = %q, want %q", scan.AgenticScanUUID, agenticUUID)
	}

	// Both of the scan's findings are stamped; the unrelated one is untouched.
	for _, id := range []int64{fid1, fid2} {
		if got := findingAgenticUUID(t, repo, id); got != agenticUUID {
			t.Errorf("finding %d AgenticScanUUID = %q, want %q", id, got, agenticUUID)
		}
	}
	if got := findingAgenticUUID(t, repo, fidOther); got != "" {
		t.Errorf("unrelated finding AgenticScanUUID = %q, want empty", got)
	}

	// Empty inputs are no-ops rather than errors.
	if err := repo.AttributeScanToAgenticScan(ctx, "", agenticUUID); err != nil {
		t.Errorf("empty scanUUID should no-op, got %v", err)
	}
	if err := repo.AttributeScanToAgenticScan(ctx, scanUUID, ""); err != nil {
		t.Errorf("empty agenticUUID should no-op, got %v", err)
	}
}

func findingAgenticUUID(t *testing.T, repo *Repository, id int64) string {
	t.Helper()
	f := &Finding{}
	if err := repo.db.NewSelect().Model(f).Where("id = ?", id).Scan(context.Background()); err != nil {
		t.Fatalf("select finding %d: %v", id, err)
	}
	return f.AgenticScanUUID
}
