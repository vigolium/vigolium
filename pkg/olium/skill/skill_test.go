package skill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	embedded "github.com/vigolium/vigolium/internal/resources/olium"
)

func TestParseValid(t *testing.T) {
	raw := []byte(`---
name: my-skill
description: does a thing
---

# Heading

body text here
`)
	s, err := Parse(raw, "/tmp/my-skill/SKILL.md", "/tmp/my-skill", SourceProjectAgents)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Name != "my-skill" {
		t.Fatalf("name = %q", s.Name)
	}
	if s.Description != "does a thing" {
		t.Fatalf("desc = %q", s.Description)
	}
	if !strings.Contains(s.Body, "body text here") {
		t.Fatalf("body = %q", s.Body)
	}
	if strings.Contains(s.Body, "---") {
		t.Fatalf("body should not contain frontmatter delimiters: %q", s.Body)
	}
}

func TestParseTags(t *testing.T) {
	raw := []byte(`---
name: tagged
description: has tags
tags:
  - XSS
  - " dom "
  - xss
  - browser-confirm
  - ""
---
body
`)
	s, err := Parse(raw, "", "", SourceEmbedded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"xss", "dom", "browser-confirm"}
	if len(s.Tags) != len(want) {
		t.Fatalf("tags = %v, want %v (lowercased, trimmed, deduped, empties dropped)", s.Tags, want)
	}
	for i := range want {
		if s.Tags[i] != want[i] {
			t.Fatalf("tags = %v, want %v", s.Tags, want)
		}
	}
}

func TestParseNoTagsIsNil(t *testing.T) {
	s, err := Parse([]byte("---\nname: untagged\ndescription: d\n---\nbody"), "", "", SourceEmbedded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Tags != nil {
		t.Fatalf("expected nil tags, got %v", s.Tags)
	}
}

func TestParseRejectsBadNames(t *testing.T) {
	cases := []string{
		"Bad_Name",
		"UPPER",
		"-leading-hyphen",
		"trailing-hyphen-",
		"double--hyphen",
		strings.Repeat("a", 65),
	}
	for _, name := range cases {
		raw := []byte("---\nname: " + name + "\ndescription: d\n---\nbody")
		if _, err := Parse(raw, "", "", SourceEmbedded); err == nil {
			t.Errorf("expected parse failure for name %q", name)
		}
	}
}

func TestParseRequiresFrontmatter(t *testing.T) {
	raw := []byte("# No frontmatter here\njust markdown")
	if _, err := Parse(raw, "", "", SourceEmbedded); err == nil {
		t.Fatalf("expected failure")
	}
}

func TestLoadEmbeddedBuiltins(t *testing.T) {
	reg, warnings, err := LoadFromEmbed(embedded.SkillsFS, embedded.SkillsPrefix, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(warnings) > 0 {
		t.Logf("warnings: %v", warnings)
	}
	if reg.Len() < 2 {
		t.Fatalf("expected ≥2 embedded skills, got %d", reg.Len())
	}
	for _, expected := range []string{"audit-auth", "triage-finding"} {
		if reg.Get(expected) == nil {
			t.Errorf("missing embedded skill %q; registered: %v", expected, names(reg))
		}
	}
}

func TestInjectIntoSystemPromptEmpty(t *testing.T) {
	out := InjectIntoSystemPrompt("base", nil)
	if out != "base" {
		t.Fatalf("nil registry should passthrough, got %q", out)
	}
}

func TestInjectIntoSystemPromptWithSkills(t *testing.T) {
	reg := &Registry{skills: map[string]*Skill{}, order: []string{}}
	reg.skills["a"] = &Skill{Name: "a", Description: "does a", Path: "/p/a/SKILL.md"}
	reg.order = append(reg.order, "a")
	out := InjectIntoSystemPrompt("base prompt", reg)
	if !strings.Contains(out, "<available_skills>") {
		t.Fatalf("missing block: %q", out)
	}
	if !strings.Contains(out, "<name>a</name>") {
		t.Fatalf("missing name: %q", out)
	}
}

func TestInjectIntoSystemPromptRendersTags(t *testing.T) {
	reg := &Registry{skills: map[string]*Skill{}, order: []string{}}
	reg.skills["tagged"] = &Skill{Name: "tagged", Description: "d", Tags: []string{"xss", "dom"}, Path: "/p/SKILL.md"}
	reg.skills["plain"] = &Skill{Name: "plain", Description: "d", Path: "/p2/SKILL.md"}
	reg.order = append(reg.order, "tagged", "plain")

	out := InjectIntoSystemPrompt("base", reg)
	if !strings.Contains(out, "<tags>xss, dom</tags>") {
		t.Fatalf("missing tags render: %q", out)
	}
	// A tagless skill must not emit an empty <tags> element.
	if strings.Contains(out, "<tags></tags>") {
		t.Fatalf("empty tags element should be omitted: %q", out)
	}
}

func TestExpandInlineInvocation(t *testing.T) {
	reg := &Registry{skills: map[string]*Skill{}, order: []string{}}
	reg.skills["x"] = &Skill{Name: "x", Description: "d", Body: "body content", Path: "/p/x/SKILL.md"}
	reg.order = append(reg.order, "x")

	out, ok := ExpandInlineInvocation(reg, "x", "do the thing")
	if !ok {
		t.Fatal("expected resolve")
	}
	if !strings.Contains(out, "body content") || !strings.Contains(out, "Task: do the thing") {
		t.Fatalf("bad expansion: %q", out)
	}

	if _, ok := ExpandInlineInvocation(reg, "missing", ""); ok {
		t.Fatal("expected miss")
	}
}

// writeSkill drops a minimal valid SKILL.md at <tmp>/<rel>/SKILL.md whose
// frontmatter name + description are both set to name.
func writeSkill(t *testing.T, tmp, rel, name string) {
	t.Helper()
	dir := filepath.Join(tmp, rel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "---\nname: " + name + "\ndescription: " + name + "\n---\nbody for " + name
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLoadProjectDiskScopes asserts the loader scans .agents/skills/ (plural)
// and .claude/skills/, and that the old misspelled .agent/skills/ (singular)
// is no longer recognized.
func TestLoadProjectDiskScopes(t *testing.T) {
	tmp := t.TempDir()
	writeSkill(t, tmp, filepath.Join(".agents", "skills", "from-agents"), "from-agents")
	writeSkill(t, tmp, filepath.Join(".claude", "skills", "from-claude"), "from-claude")
	writeSkill(t, tmp, filepath.Join(".agent", "skills", "from-agent-singular"), "from-agent-singular")

	reg, err := Load(LoadOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if reg.Get("from-agents") == nil {
		t.Errorf(".agents/skills not loaded; registered: %v", names(reg))
	}
	if reg.Get("from-claude") == nil {
		t.Errorf(".claude/skills not loaded; registered: %v", names(reg))
	}
	if reg.Get("from-agent-singular") != nil {
		t.Errorf(".agent/skills (singular) should NOT be loaded — it's the removed misspelling")
	}
}

// TestLoadProjectScopePrecedence confirms .agents wins over .claude on a
// name collision, and that the surviving skill carries the .agents source.
func TestLoadProjectScopePrecedence(t *testing.T) {
	tmp := t.TempDir()
	// Same name in both scopes; .agents is loaded first so it should win.
	writeSkill(t, tmp, filepath.Join(".agents", "skills", "dup"), "dup")
	writeSkill(t, tmp, filepath.Join(".claude", "skills", "dup"), "dup")

	reg, err := Load(LoadOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	s := reg.Get("dup")
	if s == nil {
		t.Fatal("dup not registered")
	}
	if s.Source != SourceProjectAgents {
		t.Errorf("source = %q, want %q (.agents should win)", s.Source, SourceProjectAgents)
	}
}

func names(r *Registry) []string { return r.Names() }
