package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestCreateScan_GetOrCreatePinnedUUID exercises the cross-node sync path:
// when a caller pins a scan UUID that already exists in the same project,
// CreateScan must be a no-op (not a duplicate-PK error). When the pinned
// UUID exists under a *different* project, it must surface
// ErrScanProjectMismatch so the API can reply 409 instead of corrupting
// project isolation.
func TestCreateScan_GetOrCreatePinnedUUID(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	scanUUID := uuid.NewString()
	projectA := uuid.NewString()
	projectB := uuid.NewString()

	original := &Scan{
		UUID:        scanUUID,
		ProjectUUID: projectA,
		Name:        "node-a-placeholder",
		Status:      "pending",
		StartedAt:   time.Now(),
	}
	if err := repo.CreateScan(ctx, original); err != nil {
		t.Fatalf("first CreateScan: %v", err)
	}

	// Same UUID, same project → no-op (the second-node-runs-the-scan case).
	again := &Scan{
		UUID:        scanUUID,
		ProjectUUID: projectA,
		Name:        "node-b-runner",
		Status:      "running",
		StartedAt:   time.Now(),
	}
	if err := repo.CreateScan(ctx, again); err != nil {
		t.Fatalf("get-or-create CreateScan: %v", err)
	}

	got, err := repo.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		t.Fatalf("GetScanByUUID: %v", err)
	}
	if got.Name != "node-a-placeholder" {
		t.Errorf("expected original row preserved, got name=%q", got.Name)
	}

	// Same UUID, different project → mismatch error.
	mismatch := &Scan{
		UUID:        scanUUID,
		ProjectUUID: projectB,
		Name:        "wrong-project",
		Status:      "pending",
		StartedAt:   time.Now(),
	}
	err = repo.CreateScan(ctx, mismatch)
	if !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("expected ErrScanProjectMismatch, got %v", err)
	}
}

// TestCreateAgenticScan_GetOrCreatePinnedUUID mirrors the native-scan guard
// for agentic_scans rows.
func TestCreateAgenticScan_GetOrCreatePinnedUUID(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	agenticScanUUID := uuid.NewString()
	projectA := uuid.NewString()
	projectB := uuid.NewString()

	original := &AgenticScan{
		UUID:        agenticScanUUID,
		ProjectUUID: projectA,
		Mode:        "autopilot",
		AgentName:   "olium",
		Status:      "running",
		StartedAt:   time.Now(),
	}
	if err := repo.CreateAgenticScan(ctx, original); err != nil {
		t.Fatalf("first CreateAgenticScan: %v", err)
	}

	again := &AgenticScan{
		UUID:        agenticScanUUID,
		ProjectUUID: projectA,
		Mode:        "autopilot",
		AgentName:   "olium",
		Status:      "running",
		StartedAt:   time.Now(),
	}
	if err := repo.CreateAgenticScan(ctx, again); err != nil {
		t.Fatalf("get-or-create CreateAgenticScan: %v", err)
	}

	mismatch := &AgenticScan{
		UUID:        agenticScanUUID,
		ProjectUUID: projectB,
		Mode:        "autopilot",
		AgentName:   "olium",
		Status:      "running",
		StartedAt:   time.Now(),
	}
	err := repo.CreateAgenticScan(ctx, mismatch)
	if !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("expected ErrScanProjectMismatch, got %v", err)
	}
}
