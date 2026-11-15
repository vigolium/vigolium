package runner

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func openStopTestRepo(t *testing.T, dir string) *database.Repository {
	t.Helper()
	db, err := database.NewDB(&config.DatabaseConfig{
		Enabled: true, Driver: "sqlite",
		SQLite: config.SQLiteConfig{Path: filepath.Join(dir, "stop.sqlite"), BusyTimeout: 5000, JournalMode: "WAL", Synchronous: "NORMAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return database.NewRepository(db)
}

func waitStop(t *testing.T, got <-chan StopRequest) StopRequest {
	t.Helper()
	select {
	case req := <-got:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("stop request was not delivered")
	}
	return StopRequest{}
}

// A stop request written on the row by another process reaches the running
// scan through its heartbeat, once.
func TestHeartbeatDeliversRowStopRequest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo := openStopTestRepo(t, dir)
	if err := repo.CreateScan(ctx, &database.Scan{UUID: "s-row", Status: "running", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got := make(chan StopRequest, 4)
	h := StartHeartbeat(HeartbeatConfig{Repo: repo, ScanUUID: "s-row", SessionsDir: dir,
		Interval: 20 * time.Millisecond, OnStopRequest: func(r StopRequest) { got <- r }})
	defer h.Stop(ctx)

	if ok, err := repo.RequestScanStop(ctx, "s-row", "cli:test"); err != nil || !ok {
		t.Fatalf("RequestScanStop: %v %v", ok, err)
	}
	if req := waitStop(t, got); req.By != "cli:test" {
		t.Fatalf("delivered %+v", req)
	}
	time.Sleep(100 * time.Millisecond)
	if len(got) != 0 {
		t.Fatalf("stop request delivered %d more times", len(got))
	}
}

// A scan whose row lives in a scratch database (-S, --db-isolate) is stopped
// through the session's stop sentinel, which Finish removes.
func TestHeartbeatDeliversSentinelStopRequest(t *testing.T) {
	dir := t.TempDir()
	got := make(chan StopRequest, 1)
	h := StartHeartbeat(HeartbeatConfig{ScanUUID: "s-file", SessionsDir: dir,
		Interval: 20 * time.Millisecond, OnStopRequest: func(r StopRequest) { got <- r }})
	path, err := WriteStopSentinel(dir, "s-file", "cli:file")
	if err != nil {
		t.Fatal(err)
	}
	if req := waitStop(t, got); req.By != "cli:file" {
		t.Fatalf("delivered %+v", req)
	}
	h.Finish(SessionCancelled)
	if req := readStopSentinel(path); req != nil {
		t.Fatal("Finish left the stop sentinel behind")
	}
	if _, err := WriteStopSentinel(dir, "never-ran", "x"); err == nil {
		t.Fatal("a sentinel was written for a scan with no session directory")
	}
}

// The runner turns a stop request into a cancelled run whose stop reason is
// user_stopped, and remembers who asked.
func TestRunnerHandleStopRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{ctx: ctx, cancel: cancel}
	r.handleStopRequest(StopRequest{By: "rest:project-x"})
	if ctx.Err() == nil {
		t.Fatal("stop request did not cancel the run")
	}
	if r.StopRequestedBy() != "rest:project-x" {
		t.Fatalf("StopRequestedBy = %q", r.StopRequestedBy())
	}
	if _, reason := r.scanOutcome.snapshot(); reason != database.ReasonUserStopped {
		t.Fatalf("stop reason = %q, want %q", reason, database.ReasonUserStopped)
	}
}
