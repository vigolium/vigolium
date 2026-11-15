package database

import (
	"context"
	"testing"
	"time"
)

func TestRequestScanStop(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	if err := repo.CreateScan(ctx, &Scan{UUID: "run-1", Status: "running", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateScan(ctx, &Scan{UUID: "done-1", Status: "completed", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	if req, err := repo.ScanStopRequested(ctx, "run-1"); err != nil || req != nil {
		t.Fatalf("fresh row: req=%v err=%v", req, err)
	}
	ok, err := repo.RequestScanStop(ctx, "run-1", "cli:alice@host")
	if err != nil || !ok {
		t.Fatalf("RequestScanStop running: ok=%v err=%v", ok, err)
	}
	// A second request keeps the first asker.
	if ok, err := repo.RequestScanStop(ctx, "run-1", "someone-else"); err != nil || !ok {
		t.Fatalf("second request: ok=%v err=%v", ok, err)
	}
	req, err := repo.ScanStopRequested(ctx, "run-1")
	if err != nil || req == nil || req.By != "cli:alice@host" || req.At.IsZero() {
		t.Fatalf("ScanStopRequested = %+v, %v", req, err)
	}

	if ok, err := repo.RequestScanStop(ctx, "done-1", "x"); err != nil || ok {
		t.Fatalf("finished row accepted a stop request: ok=%v err=%v", ok, err)
	}
	if ok, err := repo.RequestScanStop(ctx, "missing", "x"); err != nil || ok {
		t.Fatalf("missing row: ok=%v err=%v", ok, err)
	}

	// A full-model write of the row does not clear the request.
	if err := repo.CompleteScan(ctx, "run-1", ""); err != nil {
		t.Fatal(err)
	}
	if req, _ := repo.ScanStopRequested(ctx, "run-1"); req == nil {
		t.Fatal("completing the row dropped the stop request")
	}
}

func TestRequestAgenticScanCancel(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	live := &AgenticScan{UUID: "agent-1", Mode: "query", AgentName: "olium", Status: "running"}
	if err := repo.CreateAgenticScan(ctx, live); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{UUID: "agent-2", Mode: "query", AgentName: "olium", Status: "completed"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.AgenticScanCancelRequested(ctx, "agent-1"); got {
		t.Fatal("fresh run reports a cancel request")
	}
	ok, status, err := repo.RequestAgenticScanCancel(ctx, "agent-1")
	if err != nil || !ok || status != "running" {
		t.Fatalf("cancel live run: ok=%v status=%q err=%v", ok, status, err)
	}
	// The run's own partial update must not clear it.
	live.FindingCount = 3
	if err := repo.UpdateAgenticScan(ctx, live); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.AgenticScanCancelRequested(ctx, "agent-1"); err != nil || !got {
		t.Fatalf("cancel request lost: %v %v", got, err)
	}
	if ok, status, _ := repo.RequestAgenticScanCancel(ctx, "agent-2"); ok || status != "completed" {
		t.Fatalf("finished run: ok=%v status=%q", ok, status)
	}
	if ok, status, _ := repo.RequestAgenticScanCancel(ctx, "nope"); ok || status != "" {
		t.Fatalf("missing run: ok=%v status=%q", ok, status)
	}
}
