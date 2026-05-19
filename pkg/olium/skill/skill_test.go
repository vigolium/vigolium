package skill

import (
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
	s, err := Parse(raw, "/tmp/my-skill/SKILL.md", "/tmp/my-skill", SourceProjectAgent)
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

func names(r *Registry) []string {
	var out []string
	for _, s := range r.List() {
		out = append(out, s.Name)
	}
	return out
}
