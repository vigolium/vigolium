package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// End-to-end tests for the finding lifecycle commands (`finding mark`,
// `finding --new-since/--verdict`, `scan diff`) and the `scan <uuid>` typo
// guard. Each runs the real Execute() in a re-exec'd child against a seeded
// store, so cobra parsing, PersistentPreRunE, the envelope and the exit-code
// mapping are all exercised.

const c6ChildEnv = "VIGOLIUM_C6_ARGS"

func TestFindingLifecycleChild(t *testing.T) {
	raw := os.Getenv(c6ChildEnv)
	if raw == "" {
		t.Skip("child process helper")
	}
	os.Args = append([]string{"vigolium"}, strings.Split(raw, "\x1f")...)
	Execute()
	os.Exit(0)
}

// c6Store is a seeded store: three completed scans of one target and three
// findings — "stay" (scans 1+2), "gone" (scan 1), "fresh" (scan 2, high).
type c6Store struct {
	home, db            string
	s1, s2, s3          string
	stay, gone, fresh   int64
	stayHash, freshHash string
}

func seedC6Store(t *testing.T) *c6Store {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vigolium", initMarkerFileName), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &c6Store{home: home, db: filepath.Join(home, "c6.sqlite"),
		s1:       "c6000001-0000-4000-8000-000000000001",
		s2:       "c6000002-0000-4000-8000-000000000002",
		s3:       "c6000003-0000-4000-8000-000000000003",
		stayHash: "5a5a5a5a5a5a0000000000000000000000000001", freshHash: "f7f7f7f7f7f70000000000000000000000000003",
	}
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = st.db
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)
	start := time.Now().UTC().Add(time.Minute)
	for i, u := range []string{st.s1, st.s2, st.s3} {
		at := start.Add(time.Duration(i) * time.Hour)
		if err := repo.CreateScan(ctx, &database.Scan{
			UUID: u, ProjectUUID: database.DefaultProjectUUID, Status: "completed", Target: "https://app.example",
			StartedAt: at, FinishedAt: at.Add(time.Minute), Completeness: database.CompletenessComplete,
			PhaseOutcomes: []database.PhaseOutcome{{Phase: "dynamic-assessment", State: database.PhaseCompleted}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	save := func(hash, sev, scan string) int64 {
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, ModuleID: "m", ModuleName: "Mod " + hash[:4],
			Severity: sev, Confidence: "firm", FindingHash: hash, ScanUUID: scan, URL: "https://app.example/" + hash[:4]}
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatal(err)
		}
		var id int64
		if err := db.NewRaw("SELECT id FROM findings WHERE finding_hash = ?", hash).Scan(ctx, &id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	st.stay = save(st.stayHash, "medium", st.s1)
	save(st.stayHash, "medium", st.s2)
	st.gone = save("9090909090900000000000000000000000000002", "low", st.s1)
	st.fresh = save(st.freshHash, "high", st.s2)
	save(st.freshHash, "high", st.s3)
	return st
}

func (st *c6Store) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	full := append([]string{"--db", st.db}, args...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestFindingLifecycleChild$", "-test.v=false")
	env := []string{c6ChildEnv + "=" + strings.Join(full, "\x1f"), "HOME=" + st.home, "NO_COLOR=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "VIGOLIUM_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	}
	t.Fatalf("run child: %v", err)
	return -1, "", ""
}

// decodeOne parses stdout as exactly one JSON document.
func decodeOne(t *testing.T, stdout string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if dec.More() {
		t.Fatalf("stdout carries more than one JSON document:\n%s", stdout)
	}
	validateRegisteredDoc(t, []byte(stdout))
	return doc
}

func items(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	raw, _ := doc["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		out = append(out, it.(map[string]any))
	}
	return out
}

func TestFindingMark_EndToEnd(t *testing.T) {
	st := seedC6Store(t)

	code, out, errOut := st.run(t, "finding", "mark", "--as", "false_positive", "--note", "static asset", "--by", "alice",
		itoa(st.gone), st.freshHash[:12], "-j")
	if code != 0 {
		t.Fatalf("mark exit = %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	if doc["kind"] != "mutation" || doc["changed"] != true || doc["action"] != "update" || doc["command"] != "finding mark" {
		t.Errorf("envelope spine = kind %v changed %v action %v command %v", doc["kind"], doc["changed"], doc["action"], doc["command"])
	}
	if got := items(t, doc); len(got) != 2 || got[0]["to"] != "false_positive" || got[0]["from"] != "triaged" {
		t.Errorf("items = %v", got)
	}
	if nf, _ := doc["not_found"].([]any); len(nf) != 0 {
		t.Errorf("not_found = %v", nf)
	}

	// The verdict reads back through finding -j, with its note.
	code, out, _ = st.run(t, "finding", "--verdict", "false_positive", "-j")
	if code != 0 {
		t.Fatalf("finding --verdict exit = %d", code)
	}
	got := items(t, decodeOne(t, out))
	if len(got) != 2 || got[0]["status"] != "false_positive" || got[0]["status_note"] != "static asset" || got[0]["status_actor"] != "alice" {
		t.Errorf("finding --verdict items = %v", got)
	}

	// Repeat: unchanged, changed:false.
	code, out, _ = st.run(t, "finding", "mark", itoa(st.gone), "--as", "false_positive", "-j")
	if doc := decodeOne(t, out); code != 0 || doc["changed"] != false || len(doc["unchanged"].([]any)) != 1 {
		t.Errorf("repeat mark: exit %d doc %v", code, doc)
	}

	// A miss exits 1 after writing exactly one (result) document.
	code, out, _ = st.run(t, "finding", "mark", itoa(st.stay), "424242", "--as", "confirmed", "-j")
	if code != 1 {
		t.Fatalf("mark with a miss exit = %d, want 1", code)
	}
	doc = decodeOne(t, out)
	if errObj, _ := doc["error"].(map[string]any); doc["ok"] != false || errObj == nil || errObj["exit_code"] != float64(1) {
		t.Errorf("exit 1 keeps the result document but says ok:false with error: %v", doc)
	}
	if nf, _ := doc["not_found"].([]any); len(nf) != 1 || nf[0] != "424242" {
		t.Errorf("not_found = %v", doc["not_found"])
	}
	if doc["changed"] != true {
		t.Error("the found finding was not marked alongside the miss")
	}
}

func TestFindingMark_Refusals(t *testing.T) {
	st := seedC6Store(t)
	jsonl := filepath.Join(st.home, "export.jsonl")
	if err := os.WriteFile(jsonl, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"missing --as":   {"finding", "mark", itoa(st.stay)},
		"draft verdict":  {"finding", "mark", itoa(st.stay), "--as", "draft"},
		"short hash":     {"finding", "mark", "5a5a5a5a", "--as", "fixed"},
		"glob-db":        {"finding", "mark", itoa(st.stay), "--as", "fixed", "--glob-db", filepath.Join(st.home, "*.sqlite")},
		"jsonl db":       {"finding", "mark", itoa(st.stay), "--as", "fixed", "-S", "--db", jsonl},
		"read-only":      {"finding", "mark", itoa(st.stay), "--as", "fixed", "--read-only"},
		"ambiguous hash": {"finding", "mark", "5a5a5a5a5a5a", "--as", "fixed"},
	}
	// Make the hash prefix ambiguous for the last case.
	{
		cfg := config.DefaultDatabaseConfig()
		cfg.Driver, cfg.SQLite.Path = "sqlite", st.db
		db, err := database.NewDB(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.NewRepository(db).SaveFindingDirect(context.Background(), &database.Finding{
			ProjectUUID: database.DefaultProjectUUID, ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm",
			FindingHash: "5a5a5a5a5a5a9999999999999999999999999999"}); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := st.run(t, args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2\n%s\n%s", code, out, errOut)
			}
		})
	}
}

func TestFindingNewSince_EndToEnd(t *testing.T) {
	st := seedC6Store(t)
	code, out, errOut := st.run(t, "finding", "--new-since", st.s1, "-j")
	if code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out, errOut)
	}
	got := items(t, decodeOne(t, out))
	if len(got) != 1 || int64(got[0]["id"].(float64)) != st.fresh {
		t.Fatalf("new since s1 = %v, want only fresh (%d)", got, st.fresh)
	}
	// Dismissed findings drop out by default and come back on request.
	if code, _, _ := st.run(t, "finding", "mark", itoa(st.fresh), "--as", "accepted_risk"); code != 0 {
		t.Fatalf("mark exit = %d", code)
	}
	_, out, _ = st.run(t, "finding", "--new-since", st.s1[:8], "-j")
	if got := items(t, decodeOne(t, out)); len(got) != 0 {
		t.Errorf("dismissed finding still new: %v", got)
	}
	_, out, _ = st.run(t, "finding", "--new-since", st.s1, "--include-dismissed", "-j")
	if got := items(t, decodeOne(t, out)); len(got) != 1 {
		t.Errorf("--include-dismissed = %v", got)
	}
	// Duration form: everything was stored within the last day.
	_, out, _ = st.run(t, "finding", "--new-since", "24h", "--include-dismissed", "-j")
	if got := items(t, decodeOne(t, out)); len(got) != 3 {
		t.Errorf("--new-since 24h = %d items, want 3", len(got))
	}
	// An unknown scan is an error, not an empty answer.
	if code, _, _ := st.run(t, "finding", "--new-since", "deadbeefdead", "-j"); code != 1 {
		t.Errorf("unknown baseline exit = %d, want 1", code)
	}
	if code, _, _ := st.run(t, "finding", "--verdict", "bogus"); code != 2 {
		t.Errorf("--verdict bogus exit = %d, want 2", code)
	}
}

func TestScanDiff_EndToEnd(t *testing.T) {
	st := seedC6Store(t)
	code, out, errOut := st.run(t, "scan", "diff", st.s1, st.s2, "-j")
	if code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	if doc["command"] != "scan diff" || doc["kind"] != "read" || doc["comparable"] != true || doc["history"] != "complete" {
		t.Errorf("envelope = command %v kind %v comparable %v history %v", doc["command"], doc["kind"], doc["comparable"], doc["history"])
	}
	changes := map[int64]string{}
	for _, it := range items(t, doc) {
		changes[int64(it["id"].(float64))] = it["change"].(string)
	}
	if changes[st.fresh] != "new" || changes[st.gone] != "fixed" || changes[st.stay] != "unchanged" {
		t.Errorf("changes = %v", changes)
	}
	if counts, _ := doc["counts"].(map[string]any); counts["new"] != float64(1) || counts["not_reobserved"] != float64(0) {
		t.Errorf("counts = %v", doc["counts"])
	}

	// Keywords: latest = s3, previous = s2. fresh is unchanged there.
	_, out, _ = st.run(t, "scan", "diff", "previous", "latest", "-j")
	doc = decodeOne(t, out)
	if b, _ := doc["base"].(map[string]any); b["uuid"] != st.s2 {
		t.Errorf("previous resolved to %v", doc["base"])
	}

	// --target --last 3 compares s1 → s3; --fail-on-new trips on the high finding.
	code, out, _ = st.run(t, "scan", "diff", "--target", "https://app.example", "--last", "3", "--fail-on-new", "high", "-j")
	if code != 4 {
		t.Fatalf("--fail-on-new high exit = %d, want 4", code)
	}
	decodeOne(t, out) // the result is still the one document on stdout
	if code, _, _ := st.run(t, "scan", "diff", "--target", "https://app.example", "--fail-on-new", "critical"); code != 0 {
		t.Errorf("--fail-on-new critical exit = %d, want 0", code)
	}
	// Dismissing the new finding clears the gate.
	if code, _, _ := st.run(t, "finding", "mark", itoa(st.fresh), "--as", "false_positive"); code != 0 {
		t.Fatal("mark failed")
	}
	if code, _, _ := st.run(t, "scan", "diff", st.s1, st.s2, "--fail-on-new", "high"); code != 0 {
		t.Errorf("gate counted a dismissed finding: exit %d", code)
	}

	// Usage errors.
	for name, args := range map[string][]string{
		"one scan":        {"scan", "diff", st.s1},
		"same scan":       {"scan", "diff", st.s1, st.s1},
		"last w/o target": {"scan", "diff", st.s1, st.s2, "--last", "3"},
		"bad severity":    {"scan", "diff", st.s1, st.s2, "--fail-on-new", "huge"},
	} {
		if code, _, _ := st.run(t, args...); code != 2 {
			t.Errorf("%s: exit = %d, want 2", name, code)
		}
	}
	if code, out, _ := st.run(t, "scan", "diff", "c6ffffff", st.s2, "-j"); code != 1 || !strings.Contains(out, "scan_not_found") {
		t.Errorf("unknown scan: exit %d out %s", code, out)
	}
}

// TestScanRejectsUUIDTarget: `scan staus <uuid>` is a mistyped subcommand, not
// a scan of two hosts; a bare word alone is still a target.
func TestScanRejectsUUIDTarget(t *testing.T) {
	st := seedC6Store(t)
	code, out, errOut := st.run(t, "scan", "staus", st.s1)
	if code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out, errOut)
	}
	if all := out + errOut; !strings.Contains(all, "did you mean") && !strings.Contains(all, "Did you mean") || !strings.Contains(all, "scan status") {
		t.Errorf("error does not point at the subcommands:\n%s", all)
	}
	if err := rejectUUIDScanTargets(scanCmd, []string{"intranet", "https://app.example"}); err != nil {
		t.Errorf("bare-word target rejected: %v", err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// Unknown words on groups and on --usage are usage errors; a bare integer on
// finding is an id, and a missing one says how to search for it instead.
func TestGroupPositionalsAndUsageLookups(t *testing.T) {
	st := seedC6Store(t)
	for name, args := range map[string][]string{
		"unknown root command --usage":  {"bogus", "--usage"},
		"unknown group word --usage":    {"config", "bogus", "--usage", "-j"},
		"unknown scope component":       {"scope", "hosts", "-j"},
		"near miss of a subcommand":     {"finding", "mak", "-j"},
		"pure group under -j":           {"project", "-j"},
		"unknown word on a pure group":  {"project", "current", "-j"},
		"cobra count validator, exit 2": {"scan", "diff", st.s1},
	} {
		code, out, errOut := st.run(t, args...)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s\n%s", name, code, out, errOut)
		}
		if strings.Contains(strings.Join(args, " "), "-j") {
			doc := decodeOne(t, out)
			if doc["ok"] != false {
				t.Errorf("%s: %v", name, doc)
			}
		}
	}
	if code, out, _ := st.run(t, "module", "xss", "--usage"); code != 0 || !strings.Contains(out, "--") {
		t.Errorf("a filter word on module is still accepted by --usage: exit %d\n%s", code, out)
	}

	code, out, _ := st.run(t, "finding", "424242", "-j")
	if code != 1 {
		t.Fatalf("finding <missing id>: exit %d\n%s", code, out)
	}
	doc := decodeOne(t, out)
	errObj, _ := doc["error"].(map[string]any)
	if errObj["code"] != "finding_not_found" || !strings.Contains(fmt.Sprint(errObj["hint"]), "finding --search 424242") {
		t.Errorf("finding <missing id>: %v", doc)
	}
	code, out, _ = st.run(t, "finding", itoa(st.stay), "-j")
	if code != 0 || len(items(t, decodeOne(t, out))) != 1 {
		t.Errorf("finding <id>: exit %d\n%s", code, out)
	}
}

// `scan <verb>` is a usage error naming the command that was meant; a URL
// spelling of the same word, and any other bare word, is still a target.
func TestScanRejectsVerbTargets(t *testing.T) {
	for _, verb := range []string{"ls", "LIST", "stop", "show", "logs", "rm", "pause"} {
		err := rejectVerbScanTargets([]string{verb})
		if err == nil {
			t.Errorf("scan %s accepted as a target", verb)
			continue
		}
		if classifyExitCode(err) != ExitUsageError {
			t.Errorf("scan %s: exit %d", verb, classifyExitCode(err))
		}
		var cli clicommon.CLIError
		if !errors.As(err, &cli) || cli.Hint == "" {
			t.Errorf("scan %s: no hint: %v", verb, err)
		}
	}
	if err := rejectVerbScanTargets([]string{"http://ls", "intranet", "ls.example.com"}); err != nil {
		t.Errorf("a URL or plain host was rejected: %v", err)
	}
	st := seedC6Store(t)
	if code, out, errOut := st.run(t, "scan", "ls", "-j"); code != 2 || !strings.Contains(out, "log ls") {
		t.Errorf("scan ls: exit %d\n%s\n%s", code, out, errOut)
	}
	if code, out, _ := st.run(t, "scan", "stop", "123e4567-e89b-12d3-a456-426614174000", "-j"); code != 2 || !strings.Contains(out, "/stop") {
		t.Errorf("scan stop <uuid>: exit %d\n%s", code, out)
	}
}
