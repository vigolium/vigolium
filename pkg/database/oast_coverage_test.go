package database

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newOAST(t *testing.T, repo *Repository, projectUUID, scanUUID, protocol, moduleID string) *OASTInteraction {
	t.Helper()
	ctx := context.Background()
	oi := &OASTInteraction{
		ProjectUUID:   projectUUID,
		ScanUUID:      scanUUID,
		UniqueID:      uuid.NewString(),
		FullID:        uuid.NewString() + ".oast.example.com",
		Protocol:      protocol,
		ModuleID:      moduleID,
		TargetURL:     "https://victim.example.com/ping",
		ParameterName: "host",
		InteractedAt:  time.Now(),
	}
	if err := repo.SaveOASTInteraction(ctx, oi); err != nil {
		t.Fatalf("SaveOASTInteraction: %v", err)
	}
	return oi
}

func TestOASTInteractionsCRUD(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	scanUUID := uuid.NewString()
	a := newOAST(t, repo, DefaultProjectUUID, scanUUID, "dns", "ssrf")
	newOAST(t, repo, DefaultProjectUUID, scanUUID, "http", "ssrf")
	// Different scan.
	newOAST(t, repo, DefaultProjectUUID, uuid.NewString(), "dns", "rce")

	byScan, err := repo.GetOASTInteractionsByScan(ctx, scanUUID)
	if err != nil {
		t.Fatalf("GetOASTInteractionsByScan: %v", err)
	}
	if len(byScan) != 2 {
		t.Errorf("GetOASTInteractionsByScan = %d, want 2", len(byScan))
	}

	byID, err := repo.GetOASTInteractionByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetOASTInteractionByID: %v", err)
	}
	if byID.Protocol != "dns" {
		t.Errorf("protocol = %q", byID.Protocol)
	}

	// ListOASTInteractions with filters + pagination.
	list, total, err := repo.ListOASTInteractions(ctx, DefaultProjectUUID, scanUUID, "", "ssrf", "", 10, 0)
	if err != nil {
		t.Fatalf("ListOASTInteractions: %v", err)
	}
	if total != 2 || len(list) != 2 {
		t.Errorf("ListOASTInteractions total=%d len=%d, want 2/2", total, len(list))
	}

	// Protocol filter narrows to one.
	_, total, err = repo.ListOASTInteractions(ctx, DefaultProjectUUID, scanUUID, "http", "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListOASTInteractions(protocol): %v", err)
	}
	if total != 1 {
		t.Errorf("protocol filter total = %d, want 1", total)
	}

	// Search filter.
	_, total, err = repo.ListOASTInteractions(ctx, DefaultProjectUUID, "", "", "", "victim.example.com", 10, 0)
	if err != nil {
		t.Fatalf("ListOASTInteractions(search): %v", err)
	}
	if total != 3 {
		t.Errorf("search total = %d, want 3", total)
	}

	// Delete.
	if err := repo.DeleteOASTInteraction(ctx, a.ID); err != nil {
		t.Fatalf("DeleteOASTInteraction: %v", err)
	}
	if _, err := repo.GetOASTInteractionByID(ctx, a.ID); err == nil {
		t.Error("GetOASTInteractionByID should fail after delete")
	}

	// Nil insert errors.
	if err := repo.SaveOASTInteraction(ctx, nil); err == nil {
		t.Error("SaveOASTInteraction(nil) should error")
	}
}
