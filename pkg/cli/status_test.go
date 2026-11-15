package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestStatusOrientation(t *testing.T) {
	st := seedC6Store(t)
	repo, closeDB := openC6Repo(t, st)
	now := time.Now().UTC()
	for i := 0; i < 7; i++ {
		id := "57a70000-0000-4000-8000-00000000000" + string(rune('0'+i))
		if err := repo.CreateScan(context.Background(), &database.Scan{UUID: id, ProjectUUID: database.DefaultProjectUUID,
			Status: "running", Target: "https://running.example/" + strings.Repeat("x", 120), StartedAt: now, HeartbeatAt: &now, PID: os.Getpid()}); err != nil {
			t.Fatal(err)
		}
	}
	closeDB()

	t.Setenv("HTTPS_PROXY", "http://user:secret@127.0.0.1:1")
	code, out, errOut := st.run(t, "status", "-j")
	if code != 0 {
		t.Fatalf("status: exit %d\n%s\n%s", code, out, errOut)
	}
	if len(out) >= 2048 {
		t.Fatalf("status -j is %d bytes, want < 2048:\n%s", len(out), out)
	}
	doc := decodeOne(t, out)
	it := items(t, doc)
	if len(it) != 1 {
		t.Fatalf("items: %s", out)
	}
	v := it[0]
	if v["db_path"] == "" || v["project_source"] != "default" {
		t.Fatalf("db/project: %s", out)
	}
	counts, _ := v["counts"].(map[string]any)
	if counts == nil || counts["findings"].(float64) < 1 || counts["scans"].(float64) < 3 {
		t.Fatalf("counts: %v", v["counts"])
	}
	if running, _ := v["running"].([]any); len(running) != statusRunningLimit || v["running_total"].(float64) != 7 {
		t.Fatalf("running: %v total %v", v["running"], v["running_total"])
	}
	proxy, _ := v["proxy"].(map[string]any)
	if proxy["source"] != "env:HTTPS_PROXY" || strings.Contains(out, "secret") {
		t.Fatalf("proxy: %v (secret must be redacted)", proxy)
	}
}
