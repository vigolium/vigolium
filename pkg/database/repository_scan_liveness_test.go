package database

import (
	"context"
	"testing"
	"time"
)

func TestUpdateScanHeartbeat(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	if err := repo.CreateScan(ctx, &Scan{UUID: "hb-1", Status: "running", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	at := time.Now().UTC().Truncate(time.Millisecond)
	sent := int64(42)
	if ok, _, err := repo.UpdateScanHeartbeat(ctx, "hb-1", ScanHeartbeat{At: at, Phase: "discovery", RequestsSent: &sent, PID: 1234, Host: "box"}); err != nil || !ok {
		t.Fatalf("update = %v, %v", ok, err)
	}
	got, err := repo.GetScanByUUID(ctx, "hb-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.HeartbeatAt == nil || !got.HeartbeatAt.Equal(at) {
		t.Errorf("heartbeat_at = %v, want %v", got.HeartbeatAt, at)
	}
	if got.CurrentPhase != "discovery" || got.PID != 1234 || got.RunnerHost != "box" || got.TotalRequests != 42 {
		t.Errorf("row = phase %q pid %d host %q total %d", got.CurrentPhase, got.PID, got.RunnerHost, got.TotalRequests)
	}

	// The final beat clears the phase; a nil count leaves total_requests alone.
	if _, _, err := repo.UpdateScanHeartbeat(ctx, "hb-1", ScanHeartbeat{At: at.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetScanByUUID(ctx, "hb-1")
	if got.CurrentPhase != "" || got.TotalRequests != 42 || got.PID != 1234 {
		t.Errorf("after final beat: phase %q total %d pid %d", got.CurrentPhase, got.TotalRequests, got.PID)
	}

	// A finalized row is never re-stamped, and the caller learns it.
	if err := repo.CompleteScan(ctx, "hb-1", ""); err != nil {
		t.Fatal(err)
	}
	late := at.Add(time.Hour)
	ok, _, err := repo.UpdateScanHeartbeat(ctx, "hb-1", ScanHeartbeat{At: late, Phase: "x"})
	if err != nil || ok {
		t.Fatalf("beat on a completed row = %v, %v; want false, nil", ok, err)
	}
	got, _ = repo.GetScanByUUID(ctx, "hb-1")
	if got.HeartbeatAt.Equal(late) || got.CurrentPhase != "" {
		t.Errorf("completed row was re-stamped: %v %q", got.HeartbeatAt, got.CurrentPhase)
	}
}

func TestLastScanLogTimes(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	base := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	logs := []*ScanLog{
		{ScanUUID: "a", Level: "info", Message: "1", CreatedAt: base},
		{ScanUUID: "a", Level: "info", Message: "2", CreatedAt: base.Add(3 * time.Minute)},
		{ScanUUID: "b", Level: "info", Message: "1", CreatedAt: base.Add(time.Minute)},
		{ScanUUID: "c", Level: "info", Message: "unlisted", CreatedAt: base.Add(time.Hour)},
	}
	if err := repo.CreateScanLogBatch(ctx, logs); err != nil {
		t.Fatal(err)
	}

	got, err := repo.LastScanLogTimes(ctx, nil, []string{"a", "b", "none"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries (%v), want 2", len(got), got)
	}
	if !got["a"].Equal(base.Add(3 * time.Minute)) {
		t.Errorf("a = %v, want %v", got["a"], base.Add(3*time.Minute))
	}
	if !got["b"].Equal(base.Add(time.Minute)) {
		t.Errorf("b = %v", got["b"])
	}

	// Project-narrowed read uses the stored (defaulted) project.
	scoped, err := repo.LastScanLogTimes(ctx, []string{defaultProjectUUID("")}, []string{"a"})
	if err != nil || scoped["a"].IsZero() {
		t.Fatalf("scoped = %v, %v", scoped, err)
	}
	empty, err := repo.LastScanLogTimes(ctx, []string{"other-project"}, []string{"a"})
	if err != nil || len(empty) != 0 {
		t.Fatalf("other project = %v, %v", empty, err)
	}
}
