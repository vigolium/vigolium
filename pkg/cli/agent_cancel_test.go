package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestWatchAgentCancel(t *testing.T) {
	prev := agentCancelPollInterval
	agentCancelPollInterval = 20 * time.Millisecond
	t.Cleanup(func() { agentCancelPollInterval = prev })

	st := seedC6Store(t)
	repo, closeDB := openC6Repo(t, st)
	defer closeDB()
	bg := context.Background()
	if err := repo.CreateAgenticScan(bg, &database.AgenticScan{UUID: "a9e00001-0000-4000-8000-000000000001", Mode: "query", AgentName: "olium", Status: "running"}); err != nil {
		t.Fatal(err)
	}

	// The row's cancel request cancels the run's context.
	ctx, stop := watchAgentCancel(bg, repo, "", "a9e00001-0000-4000-8000-000000000001")
	defer stop()
	if _, _, err := repo.RequestAgenticScanCancel(bg, "a9e00001-0000-4000-8000-000000000001"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("cancel request did not cancel the run")
	}
	if !errors.Is(ctx.Err(), context.Canceled) || !errors.Is(context.Cause(ctx), errAgentCancelRequested) {
		t.Fatalf("err=%v cause=%v", ctx.Err(), context.Cause(ctx))
	}
	if err := agentRunFailure(ctx, ctx.Err()); !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("agentRunFailure = %v", err)
	}
	if activeAgentRunUUID() != "a9e00001-0000-4000-8000-000000000001" {
		t.Fatalf("active run = %q", activeAgentRunUUID())
	}

	// The sentinel does the same for a run whose row is out of reach; stop
	// removes it.
	dir := t.TempDir()
	ctx2, stop2 := watchAgentCancel(bg, nil, dir, "a9e00002-0000-4000-8000-000000000002")
	if err := writeAgentCancelSentinel(dir); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx2.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("sentinel did not cancel the run")
	}
	stop2()
	if _, err := os.Stat(filepath.Join(dir, agentCancelFilename)); !os.IsNotExist(err) {
		t.Fatalf("sentinel left behind: %v", err)
	}

	// The error envelope names the run.
	env := outcomeErrorEnvelope(errors.New("boom"), 1, nil)
	raw, _ := json.Marshal(env)
	if !strings.Contains(string(raw), `"agentic_scan_uuid":"a9e00002-0000-4000-8000-000000000002"`) {
		t.Fatalf("error envelope: %s", raw)
	}
}

func TestAgentCancelCommand(t *testing.T) {
	st := seedC6Store(t)
	repo, closeDB := openC6Repo(t, st)
	bg := context.Background()
	const live, done = "a9e10001-0000-4000-8000-000000000001", "a9e10002-0000-4000-8000-000000000002"
	for _, r := range []*database.AgenticScan{
		{UUID: live, ProjectUUID: database.DefaultProjectUUID, Mode: "autopilot", AgentName: "olium", Status: "running"},
		{UUID: done, ProjectUUID: database.DefaultProjectUUID, Mode: "query", AgentName: "olium", Status: "completed"},
	} {
		if err := repo.CreateAgenticScan(bg, r); err != nil {
			t.Fatal(err)
		}
	}
	closeDB()

	code, out, errOut := st.run(t, "agent", "cancel", live[:9], "-j")
	if code != 0 {
		t.Fatalf("agent cancel: exit %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	if doc["action"] != "cancel_requested" || doc["changed"] != true {
		t.Fatalf("agent cancel doc: %s", out)
	}
	repo, closeDB = openC6Repo(t, st)
	if ok, err := repo.AgenticScanCancelRequested(bg, live); err != nil || !ok {
		t.Fatalf("cancel request not recorded: %v %v", ok, err)
	}
	closeDB()

	code, out, _ = st.run(t, "agent", "cancel", done, "-j")
	if doc := decodeOne(t, out); code != 0 || doc["action"] != "already_finished" || doc["changed"] != false {
		t.Fatalf("finished run: exit %d\n%s", code, out)
	}
	if code, out, _ := st.run(t, "agent", "cancel", "a9e1ffff", "-j"); code != 1 || !strings.Contains(out, "not_found") {
		t.Fatalf("unknown run: exit %d\n%s", code, out)
	}

	// agent session accepts a prefix.
	code, out, errOut = st.run(t, "agent", "session", done[:8], "-j")
	if code != 0 || !strings.Contains(out, done) {
		t.Fatalf("agent session <prefix>: exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestAuditDryRunAndBudgetFlags(t *testing.T) {
	st := seedC6Store(t)
	src := t.TempDir()
	code, out, errOut := st.run(t, "audit", "--source", src, "--driver", "piolium", "--dry-run", "--max-duration", "90m", "-j")
	if code != 0 {
		t.Fatalf("audit --dry-run: exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, `"driver":"piolium"`) || !strings.Contains(out, `"max_duration_ms":5400000`) {
		t.Fatalf("audit --dry-run doc: %s", out)
	}
	if entries, _ := os.ReadDir(filepath.Join(st.home, ".vigolium", "agent-sessions")); len(entries) != 0 {
		t.Fatalf("a dry run created %d session dir(s)", len(entries))
	}
	for _, flag := range []string{"--max-cost-usd=5", "--token-budget=1000"} {
		code, out, _ := st.run(t, "audit", "--source", src, flag, "-j")
		if code != 2 || !strings.Contains(out, "not supported on audit") {
			t.Errorf("%s: exit %d\n%s", flag, code, out)
		}
	}
}
