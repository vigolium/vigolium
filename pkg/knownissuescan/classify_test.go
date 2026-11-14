package knownissuescan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestClassifyRootOnly(t *testing.T) {
	cases := []struct {
		name, body string
		want       bool
	}{
		{"root", "id: root-tpl\nhttp:\n  - method: GET\n    path:\n      - \"{{RootURL}}/server-status\"\n", true},
		{"base", "id: base-tpl\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/.env\"\n", false},
		{"both", "id: both\nhttp:\n  - path:\n      - \"{{RootURL}}/a\"\n      - \"{{BaseURL}}/b\"\n", false},
		{"ssl", "id: tls-tpl\nssl:\n  - address: \"{{Host}}:{{Port}}\"\n", true},
		{"dns", "id: dns-tpl\ndns:\n  - name: \"{{FQDN}}\"\n", true},
		{"noid", "http:\n  - path: [\"{{RootURL}}\"]\n", false},
	}
	for _, tc := range cases {
		_, got := classifyRootOnly([]byte(tc.body))
		if got != tc.want {
			t.Errorf("%s: rootOnly = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPlanPasses_PrefixPassExcludesRootOnly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yaml", "id: server-status\nhttp:\n  - path: [\"{{RootURL}}/server-status\"]\n")
	write("b.yaml", "id: dotenv\nhttp:\n  - path: [\"{{BaseURL}}/.env\"]\n")

	cfg := Config{TemplatesDir: dir, Targets: []string{"https://a"}, PrefixTargets: []string{"https://a/app"}}
	passes := planPasses(cfg)
	if len(passes) != 2 {
		t.Fatalf("passes = %d, want origin pass + prefix pass", len(passes))
	}
	if !slices.Equal(passes[0].targets, []string{"https://a"}) || len(passes[0].excludeIDs) != 0 {
		t.Fatalf("origin pass = %+v", passes[0])
	}
	if !slices.Equal(passes[1].targets, []string{"https://a/app"}) || !slices.Equal(passes[1].excludeIDs, []string{"server-status"}) {
		t.Fatalf("prefix pass = %+v", passes[1])
	}

	// No prefixes: one pass, no exclusions.
	if p := planPasses(Config{TemplatesDir: dir, Targets: []string{"https://a"}}); len(p) != 1 || len(p[0].excludeIDs) != 0 {
		t.Fatalf("single pass expected, got %+v", p)
	}
	// Explicit template list: classification skipped, one combined pass.
	if p := planPasses(Config{TemplatesDir: dir, Templates: []string{"b.yaml"}, Targets: []string{"https://a"}, PrefixTargets: []string{"https://a/app"}}); len(p) != 1 || len(p[0].targets) != 2 {
		t.Fatalf("combined pass expected, got %+v", p)
	}
}
