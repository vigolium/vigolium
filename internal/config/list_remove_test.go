package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListRemoveOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte("# keep me\nscope:\n  host:\n    exclude: [\"a.example\", \"b.example\", \"c.example\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if SettingPath("scope.host.exclude.remove") != "scope.host.exclude" {
		t.Fatalf("SettingPath(.remove) = %q", SettingPath("scope.host.exclude.remove"))
	}
	edit, err := SetFieldEdit(settings, "scope.host.exclude.remove", "b.example")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(settings.Scope.Host.Exclude, ","); got != "a.example,c.example" {
		t.Fatalf("in-memory list after remove = %q", got)
	}
	if _, err := EditConfigFile(path, edit); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "b.example") || !strings.Contains(string(data), "# keep me") || !strings.Contains(string(data), "c.example") {
		t.Fatalf("file after remove:\n%s", data)
	}
	// Removing what is not there changes nothing.
	settings, _ = LoadSettings(path)
	edit, err = SetFieldEdit(settings, "scope.host.exclude.remove", `["zzz.example"]`)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := EditConfigFile(path, edit); err != nil || changed {
		t.Fatalf("removing an absent item: changed=%v err=%v", changed, err)
	}
}

func TestScopeRejectDetail(t *testing.T) {
	cfg := DefaultScopeConfig()
	cfg.Host.Exclude = []string{"*.internal.example"}
	cfg.Path.Exclude = []string{"/admin/*"}
	m := NewScopeMatcher(*cfg)
	for _, c := range []struct{ host, path, rule, pattern string }{
		{"db.internal.example", "/", ScopeRuleHostExclude, "*.internal.example"},
		{"app.example", "/admin/users", ScopeRulePathExclude, "/admin/*"},
		{"app.example", "/ok", "", ""},
	} {
		rule, pattern := m.RejectDetail(c.host, c.path)
		if rule != c.rule || pattern != c.pattern {
			t.Errorf("RejectDetail(%s, %s) = %q %q, want %q %q", c.host, c.path, rule, pattern, c.rule, c.pattern)
		}
	}
}
