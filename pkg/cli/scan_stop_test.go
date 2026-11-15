package cli

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
)

func openC6Repo(t *testing.T, st *c6Store) (*database.Repository, func()) {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = st.db
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return database.NewRepository(db), func() { _ = db.Close() }
}

func TestScanStopAndLs(t *testing.T) {
	st := seedC6Store(t)
	ctx := context.Background()
	const (
		live      = "5ca10001-0000-4000-8000-000000000001"
		abandoned = "5ca10002-0000-4000-8000-000000000002"
		scratch   = "5ca10003-0000-4000-8000-000000000003"
	)
	repo, closeDB := openC6Repo(t, st)
	now := time.Now().UTC()
	old := now.Add(-time.Hour)
	if err := repo.CreateScan(ctx, &database.Scan{UUID: live, ProjectUUID: database.DefaultProjectUUID, Status: "running",
		StartedAt: now, HeartbeatAt: &now, PID: os.Getpid()}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateScan(ctx, &database.Scan{UUID: abandoned, ProjectUUID: database.DefaultProjectUUID, Status: "running",
		StartedAt: old, HeartbeatAt: &old, CreatedAt: old, UpdatedAt: old}); err != nil {
		t.Fatal(err)
	}
	closeDB()

	// The live scan gets a stop request on its row, and on its session
	// sentinel since its session directory exists on this host.
	sessions := filepath.Join(st.home, ".vigolium", "native-sessions")
	if err := os.MkdirAll(filepath.Join(sessions, live), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := st.run(t, "scan", "stop", live[:8], "-j")
	if code != 0 {
		t.Fatalf("scan stop live: exit %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	it := items(t, doc)
	if doc["changed"] != true || doc["action"] != stopActionRequested || len(it) != 1 || it[0]["scan_uuid"] != live {
		t.Fatalf("scan stop live doc: %s", out)
	}
	if via, _ := it[0]["via"].([]any); len(via) != 2 {
		t.Fatalf("via = %v, want db and sentinel", it[0]["via"])
	}
	repo, closeDB = openC6Repo(t, st)
	if req, err := repo.ScanStopRequested(ctx, live); err != nil || req == nil || !strings.HasPrefix(req.By, "cli") {
		t.Fatalf("stop request on the row = %+v, %v", req, err)
	}
	closeDB()
	if _, err := os.Stat(runner.SessionStopPath(sessions, live)); err != nil {
		t.Fatalf("stop sentinel: %v", err)
	}

	// A running row whose process is gone is reaped, not asked.
	code, out, _ = st.run(t, "scan", "stop", abandoned, "-j")
	if code != 0 {
		t.Fatalf("scan stop abandoned: exit %d\n%s", code, out)
	}
	if doc := decodeOne(t, out); doc["action"] != stopActionReaped || doc["changed"] != true {
		t.Fatalf("scan stop abandoned doc: %s", out)
	}
	repo, closeDB = openC6Repo(t, st)
	row, err := repo.GetScanByUUID(ctx, abandoned)
	closeDB()
	if err != nil || row.Status != "failed" || row.StopReason != database.ReasonAbandoned {
		t.Fatalf("abandoned row after stop = %+v, %v", row, err)
	}

	// A finished scan is left alone.
	code, out, _ = st.run(t, "scan", "stop", st.s1, "-j")
	if doc := decodeOne(t, out); code != 0 || doc["action"] != stopActionAlreadyFinished || doc["changed"] != false {
		t.Fatalf("scan stop finished: exit %d\n%s", code, out)
	}

	// A -S scan's row is in a scratch file: only status.json and the
	// sentinel exist on this host.
	if err := os.MkdirAll(filepath.Join(sessions, scratch), 0o755); err != nil {
		t.Fatal(err)
	}
	stJSON := `{"scan_uuid":"` + scratch + `","pid":` + strconv.Itoa(os.Getpid()) + `,"status":"running","phases_done":[],"started_at":"` +
		now.Format(time.RFC3339Nano) + `","heartbeat_at":"` + now.Format(time.RFC3339Nano) + `"}`
	if err := os.WriteFile(runner.SessionStatusPath(sessions, scratch), []byte(stJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = st.run(t, "scan", "stop", scratch[:10], "-j")
	if code != 0 {
		t.Fatalf("scan stop scratch: exit %d\n%s\n%s", code, out, errOut)
	}
	if it := items(t, decodeOne(t, out)); len(it) != 1 || len(it[0]["via"].([]any)) != 1 || it[0]["via"].([]any)[0] != "sentinel" {
		t.Fatalf("scan stop scratch doc: %s", out)
	}

	// Unknown and ambiguous references.
	if code, out, _ := st.run(t, "scan", "stop", "deadbeef", "-j"); code != 1 || !strings.Contains(out, "scan_not_found") {
		t.Fatalf("unknown prefix: exit %d\n%s", code, out)
	}
	if code, out, _ := st.run(t, "scan", "stop", "5ca1000", "-j"); code != 2 || !strings.Contains(out, "too short") {
		t.Fatalf("short prefix message: %s", out)
	}
	if code, out, _ := st.run(t, "scan", "stop", "5ca10001-0000", "-j"); code != 0 {
		t.Fatalf("longer prefix: exit %d\n%s", code, out)
	}
	if code, out, _ := st.run(t, "scan", "stop", "5ca10001-0000-4000-8000-00000000000", "-j"); code != 0 {
		t.Fatalf("near-full prefix: exit %d\n%s", code, out)
	}
	_ = os.MkdirAll(filepath.Join(sessions, "5ca10001-0000-4000-8000-000000000009"), 0o755)
	if code, out, _ := st.run(t, "scan", "stop", "5ca10001", "-j"); code != 1 || !strings.Contains(out, "ambiguous_id") {
		t.Fatalf("ambiguous prefix: exit %d\n%s", code, out)
	}

	// scan ls is log ls under another name.
	code, out, errOut = st.run(t, "scan", "ls", "-j")
	if code != 0 {
		t.Fatalf("scan ls: exit %d\n%s\n%s", code, out, errOut)
	}
	if doc := decodeOne(t, out); doc["command"] != "scan ls" || len(items(t, doc)) == 0 {
		t.Fatalf("scan ls doc: %s", out)
	}
}
