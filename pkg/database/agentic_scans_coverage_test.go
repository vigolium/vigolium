package database

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newAgenticScan(t *testing.T, repo *Repository, projectUUID, mode, parent string) *AgenticScan {
	t.Helper()
	ctx := context.Background()
	a := &AgenticScan{
		UUID:                  uuid.NewString(),
		ProjectUUID:           projectUUID,
		Mode:                  mode,
		AgentName:             "olium",
		Status:                "completed",
		ParentAgenticScanUUID: parent,
		CompletedAt:           time.Now(),
	}
	if err := repo.CreateAgenticScan(ctx, a); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}
	return a
}

func TestAgenticScanListingAndChildren(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	proj := uuid.NewString()
	parent := newAgenticScan(t, repo, proj, "swarm", "")
	// Two children of the parent (must be excluded from top-level list).
	newAgenticScan(t, repo, proj, "scan", parent.UUID)
	newAgenticScan(t, repo, proj, "scan", parent.UUID)
	// Another top-level run with a different mode.
	newAgenticScan(t, repo, proj, "autopilot", "")

	// ListAgenticScans returns only top-level (parentless) runs.
	runs, total, err := repo.ListAgenticScans(ctx, proj, "", 50, 0)
	if err != nil {
		t.Fatalf("ListAgenticScans: %v", err)
	}
	if total != 2 || len(runs) != 2 {
		t.Errorf("ListAgenticScans total=%d len=%d, want 2/2 top-level", total, len(runs))
	}

	// Mode filter.
	_, total, err = repo.ListAgenticScans(ctx, proj, "swarm", 50, 0)
	if err != nil {
		t.Fatalf("ListAgenticScans(mode): %v", err)
	}
	if total != 1 {
		t.Errorf("mode filter total = %d, want 1", total)
	}

	// GetChildAgenticScans.
	children, err := repo.GetChildAgenticScans(ctx, parent.UUID)
	if err != nil {
		t.Fatalf("GetChildAgenticScans: %v", err)
	}
	if len(children) != 2 {
		t.Errorf("GetChildAgenticScans = %d, want 2", len(children))
	}
}

func TestUpdateAgenticScanStorageURL(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	a := newAgenticScan(t, repo, DefaultProjectUUID, "query", "")
	if err := repo.UpdateAgenticScanStorageURL(ctx, a.UUID, "gs://bucket/run"); err != nil {
		t.Fatalf("UpdateAgenticScanStorageURL: %v", err)
	}
	got, _ := repo.GetAgenticScan(ctx, a.UUID)
	if got.StorageURL != "gs://bucket/run" {
		t.Errorf("storage_url = %q", got.StorageURL)
	}
}

func TestDeleteOldAgenticScans(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// An old completed run.
	old := &AgenticScan{
		UUID:        uuid.NewString(),
		ProjectUUID: DefaultProjectUUID,
		Mode:        "query",
		AgentName:   "olium",
		Status:      "completed",
		CompletedAt: time.Now().Add(-48 * time.Hour),
	}
	if err := repo.CreateAgenticScan(ctx, old); err != nil {
		t.Fatalf("CreateAgenticScan(old): %v", err)
	}
	// A fresh one that must survive.
	newAgenticScan(t, repo, DefaultProjectUUID, "query", "")

	deleted, err := repo.DeleteOldAgenticScans(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("DeleteOldAgenticScans: %v", err)
	}
	if deleted != 1 {
		t.Errorf("DeleteOldAgenticScans = %d, want 1", deleted)
	}
}

func TestCreateAgenticScanProjectMismatch(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	id := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{UUID: id, ProjectUUID: "p1", Mode: "query", AgentName: "olium"}); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{UUID: id, ProjectUUID: "p2", Mode: "query", AgentName: "olium"}); err == nil {
		t.Error("expected ErrScanProjectMismatch on cross-project re-create")
	}
}
