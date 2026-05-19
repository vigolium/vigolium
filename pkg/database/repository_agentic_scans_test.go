package database

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestUpdateAgenticScan_OmitZeroPreservesCallerFields guards the OmitZero
// behavior of UpdateAgenticScan: callers (the API server's enrichAgenticScanRecord
// helpers and SwarmRunner.Run) hand in partial structs containing only the
// fields they want to write. Without OmitZero, every other column got
// silently zeroed each time, which is why the swarm runner had to be
// followed by a re-enrich block in the API handler. This test pins the
// preserve-untouched-fields contract so future refactors can't regress it.
func TestUpdateAgenticScan_OmitZeroPreservesCallerFields(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	agenticScanUUID := uuid.NewString()
	original := &AgenticScan{
		UUID:        agenticScanUUID,
		ProjectUUID: DefaultProjectUUID,
		Mode:        "swarm",
		AgentName:   "olium",
		Status:      "running",
		SourcePath:  "/work/some-repo",
		SourceType:  "local",
		TargetURL:   "https://example.test",
		SessionDir:  "/tmp/sessions/" + agenticScanUUID,
		InputRaw:    "https://example.test/api/login",
		StartedAt:   time.Now(),
	}
	if err := repo.CreateAgenticScan(ctx, original); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}

	// Simulate the swarm runner's completion update: a fresh struct with
	// only the fields the runner knows about. Pre-OmitZero, this would
	// have nulled source_path/target_url/session_dir/input_raw.
	runnerUpdate := &AgenticScan{
		UUID:         agenticScanUUID,
		Status:       "completed",
		FindingCount: 7,
		DurationMs:   42_000,
		CompletedAt:  time.Now(),
	}
	if err := repo.UpdateAgenticScan(ctx, runnerUpdate); err != nil {
		t.Fatalf("UpdateAgenticScan: %v", err)
	}

	got, err := repo.GetAgenticScan(ctx, agenticScanUUID)
	if err != nil {
		t.Fatalf("GetAgenticScan: %v", err)
	}

	// Runner-set fields took effect.
	if got.Status != "completed" {
		t.Errorf("status not updated: got %q", got.Status)
	}
	if got.FindingCount != 7 {
		t.Errorf("finding_count not updated: got %d", got.FindingCount)
	}
	if got.DurationMs != 42_000 {
		t.Errorf("duration_ms not updated: got %d", got.DurationMs)
	}

	// Caller-set fields the runner doesn't know about must survive intact.
	if got.SourcePath != original.SourcePath {
		t.Errorf("source_path clobbered: got %q want %q", got.SourcePath, original.SourcePath)
	}
	if got.TargetURL != original.TargetURL {
		t.Errorf("target_url clobbered: got %q want %q", got.TargetURL, original.TargetURL)
	}
	if got.SessionDir != original.SessionDir {
		t.Errorf("session_dir clobbered: got %q want %q", got.SessionDir, original.SessionDir)
	}
	if got.InputRaw != original.InputRaw {
		t.Errorf("input_raw clobbered: got %q want %q", got.InputRaw, original.InputRaw)
	}
	if got.SourceType != original.SourceType {
		t.Errorf("source_type clobbered: got %q want %q", got.SourceType, original.SourceType)
	}
}
