package cli

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every --dry-run reports dry_run:true and changed:false through the mutation
// envelope, exits 0, and leaves the state it would have changed untouched.
func TestDryRunMutatesNothing(t *testing.T) {
	st := seedC6Store(t)
	ctx := context.Background()
	cfgPath := filepath.Join(st.home, ".vigolium", "vigolium-configs.yaml")
	if err := os.WriteFile(cfgPath, []byte("# kept\nnotify:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgBefore, _ := os.ReadFile(cfgPath)
	dbInfo := func() int64 {
		fi, err := os.Stat(st.db)
		if err != nil {
			t.Fatalf("database gone: %v", err)
		}
		return fi.Size()
	}

	// A project to (not) delete.
	code, out, _ := st.run(t, "project", "create", "dryrun-target", "-j")
	if code != 0 {
		t.Fatalf("project create: exit %d\n%s", code, out)
	}
	projUUID := items(t, decodeOne(t, out))[0]["uuid"].(string)

	dir := t.TempDir()
	findingsFile := filepath.Join(dir, "f.jsonl")
	_ = os.WriteFile(findingsFile, []byte(`{"title":"Dry finding","severity":"high","url":"https://dry.example/"}`+"\n"), 0o600)
	urls := filepath.Join(dir, "urls.txt")
	_ = os.WriteFile(urls, []byte("http://127.0.0.1:1/a\nhttp://127.0.0.1:1/b\n"), 0o600)
	sessFile := filepath.Join(dir, "s.yaml")
	_ = os.WriteFile(sessFile, []byte("name: static\nheaders:\n  Authorization: Bearer x\n"), 0o600)
	skillsDir := filepath.Join(dir, "skills")

	// An export holding a finding st does not have, for import.
	src := seedC6Store(t)
	if code, out, _ := src.run(t, "finding", "load", findingsFile, "-j"); code != 0 {
		t.Fatalf("seed export source: exit %d\n%s", code, out)
	}
	exportFile := filepath.Join(dir, "export.jsonl")
	if code, out, errOut := src.run(t, "export", "--format", "jsonl", "-o", exportFile); code != 0 {
		t.Fatalf("export: exit %d\n%s\n%s", code, out, errOut)
	}

	repo, closeDB := openC6Repo(t, st)
	f, err := repo.GetFindingByID(ctx, st.fresh)
	closeDB()
	if err != nil {
		t.Fatal(err)
	}
	statusBefore := f.Status

	cases := []struct {
		name string
		args []string
	}{
		{"db reset", []string{"db", "reset", "--dry-run"}},
		{"project delete", []string{"project", "delete", projUUID, "--dry-run"}},
		{"module disable", []string{"module", "disable", "reflected-ssti", "--id", "--dry-run"}},
		{"finding load", []string{"finding", "load", findingsFile, "--dry-run"}},
		{"finding mark", []string{"finding", "mark", strconv.FormatInt(st.fresh, 10), "--as", "false_positive", "--dry-run"}},
		{"ingest", []string{"ingest", "-i", urls, "--dry-run"}},
		{"import", []string{"import", exportFile, "--dry-run"}},
		{"skills install", []string{"skills", "install", "--dir", skillsDir, "--dry-run"}},
		{"scope set", []string{"scope", "set", "host.include", `["dry.example"]`, "--dry-run"}},
		{"auth load", []string{"auth", "load", sessFile, "--host", "static.example", "--dry-run"}},
		{"config set", []string{"config", "set", "notify.enabled", "true", "--dry-run"}},
	}
	for _, c := range cases {
		code, out, errOut := st.run(t, append(c.args, "-j")...)
		if code != 0 {
			t.Errorf("%s --dry-run: exit %d\n%s\n%s", c.name, code, out, errOut)
			continue
		}
		doc := decodeOne(t, out)
		if doc["dry_run"] != true || doc["changed"] != false {
			t.Errorf("%s --dry-run: dry_run=%v changed=%v\n%s", c.name, doc["dry_run"], doc["changed"], out)
		}
		if c.name == "ingest" && doc["would_ingest"] != float64(2) {
			t.Errorf("ingest --dry-run would_ingest = %v\n%s", doc["would_ingest"], out)
		}
	}

	if dbInfo() == 0 {
		t.Fatal("db reset --dry-run emptied the database")
	}
	if cfgAfter, _ := os.ReadFile(cfgPath); string(cfgAfter) != string(cfgBefore) {
		t.Fatalf("a dry run edited the config:\n%s", cfgAfter)
	}
	if _, err := os.Stat(skillsDir); !os.IsNotExist(err) {
		t.Fatalf("skills install --dry-run wrote %s", skillsDir)
	}
	repo, closeDB = openC6Repo(t, st)
	defer closeDB()
	if p, err := repo.GetProjectByUUID(ctx, projUUID); err != nil || p == nil {
		t.Fatalf("project delete --dry-run deleted the project: %v", err)
	}
	if f, _ := repo.GetFindingByID(ctx, st.fresh); f.Status != statusBefore {
		t.Fatalf("finding mark --dry-run changed status %q -> %q", statusBefore, f.Status)
	}
	var n int
	if err := repo.DB().NewRaw("SELECT COUNT(*) FROM findings WHERE module_id = 'dry-1' OR url LIKE '%dry.example%'").Scan(ctx, &n); err != nil || n != 0 {
		t.Fatalf("finding load --dry-run stored %d finding(s) (%v)", n, err)
	}
	if err := repo.DB().NewRaw("SELECT COUNT(*) FROM http_records WHERE url LIKE 'http://127.0.0.1:1/%'").Scan(ctx, &n); err != nil || n != 0 {
		t.Fatalf("ingest --dry-run stored %d record(s) (%v)", n, err)
	}
	if code, out, _ := st.run(t, "auth", "ls", "-j"); code == 0 && strings.Contains(out, `"static"`) {
		t.Fatalf("auth load --dry-run saved the session:\n%s", out)
	}
}
