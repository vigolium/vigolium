package cli

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestGettersAndRemovers(t *testing.T) {
	st := seedC6Store(t)
	ctx := context.Background()
	cfgPath := filepath.Join(st.home, ".vigolium", "vigolium-configs.yaml")
	if err := os.WriteFile(cfgPath, []byte("# top\nnotify:\n  enabled: true\nscope:\n  host:\n    exclude: [\"a.example\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(want int, args ...string) map[string]any {
		t.Helper()
		code, out, errOut := st.run(t, append(args, "-j")...)
		if code != want {
			t.Fatalf("%v: exit %d, want %d\n%s\n%s", args, code, want, out, errOut)
		}
		return decodeOne(t, out)
	}
	first := func(doc map[string]any) map[string]any {
		t.Helper()
		it := items(t, doc)
		if len(it) == 0 {
			t.Fatalf("no items: %v", doc)
		}
		return it[0]
	}

	// config get / unset
	if v := first(run(0, "config", "get", "notify.enabled")); v["value"] != true || v["source"] != "file" {
		t.Fatalf("config get notify.enabled = %v", v)
	}
	if doc := run(2, "config", "get", "notify.enabeld"); !strings.Contains(doc["error"].(map[string]any)["did_you_mean"].(string), "notify.enabled") {
		t.Fatalf("config get typo: %v", doc)
	}
	if doc := run(0, "config", "unset", "notify.enabled"); doc["changed"] != true {
		t.Fatalf("config unset: %v", doc)
	}
	data, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(data), "enabled: true") || !strings.Contains(string(data), "# top") {
		t.Fatalf("config after unset:\n%s", data)
	}
	if doc := run(0, "config", "unset", "notify.enabled"); doc["changed"] != false || doc["action"] != "noop" {
		t.Fatalf("config unset again: %v", doc)
	}

	// scope add / rm / check
	if doc := run(0, "scope", "add", "host", "b.example", "c.example", "--exclude"); doc["changed"] != true {
		t.Fatalf("scope add: %v", doc)
	}
	if doc := run(0, "scope", "rm", "host", "a.example", "--exclude"); doc["changed"] != true {
		t.Fatalf("scope rm: %v", doc)
	}
	data, _ = os.ReadFile(cfgPath)
	if strings.Contains(string(data), "a.example") || !strings.Contains(string(data), "c.example") {
		t.Fatalf("config after scope add/rm:\n%s", data)
	}
	if v := first(run(0, "scope", "check", "https://b.example/x")); v["in_scope"] != false || v["rule"] != "scope.host.exclude" || v["pattern"] != "b.example" {
		t.Fatalf("scope check excluded: %v", v)
	}
	if v := first(run(0, "scope", "check", "https://ok.example/")); v["in_scope"] != true {
		t.Fatalf("scope check in scope: %v", v)
	}

	// auth show / rm
	sessFile := filepath.Join(t.TempDir(), "s.yaml")
	_ = os.WriteFile(sessFile, []byte("name: static\nheaders:\n  Authorization: Bearer topsecret\n"), 0o600)
	run(0, "auth", "load", sessFile, "--host", "static.example")
	code, out, _ := st.run(t, "auth", "show", "static", "-j")
	if code != 0 || strings.Contains(out, "topsecret") || !strings.Contains(out, "static.example") {
		t.Fatalf("auth show: exit %d\n%s", code, out)
	}
	run(1, "auth", "show", "nobody")
	if doc := run(0, "auth", "rm", "static", "--dry-run"); doc["dry_run"] != true {
		t.Fatalf("auth rm --dry-run: %v", doc)
	}
	run(0, "auth", "show", "static")
	if doc := run(0, "auth", "rm", "static"); doc["changed"] != true {
		t.Fatalf("auth rm: %v", doc)
	}
	run(1, "auth", "show", "static")

	// project current / rename
	if v := first(run(0, "project", "current")); v["uuid"] != database.DefaultProjectUUID || v["source"] != "default" {
		t.Fatalf("project current: %v", v)
	}
	created := first(run(0, "project", "create", "before-name"))
	if doc := run(0, "project", "rename", "before-name", "after-name"); first(doc)["previous_name"] != "before-name" || first(doc)["name"] != "after-name" {
		t.Fatalf("project rename: %v", doc)
	}
	run(2, "project", "rename", created["uuid"].(string), "Default Project")

	// module show
	if v := first(run(0, "module", "show", "reflected-ssti")); v["id"] != "reflected-ssti" || v["description"] == "" {
		t.Fatalf("module show: %v", v)
	}
	run(1, "module", "show", "no-such-module-zzz")

	// finding show (and the bare-int form still treated as an id)
	doc := run(0, "finding", "show", strconv.FormatInt(st.fresh, 10))
	if len(items(t, doc)) != 1 {
		t.Fatalf("finding show: %v", doc)
	}
	doc = run(1, "finding", "show", strconv.FormatInt(st.fresh, 10), "999999")
	if nf, _ := doc["not_found"].([]any); len(nf) != 1 {
		t.Fatalf("finding show with a missing id: %v", doc)
	}
	_ = ctx
}
