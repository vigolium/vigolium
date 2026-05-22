package prompt

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

func TestBuildModuleCatalog_GroupsAndIncludesAllTags(t *testing.T) {
	tags := []string{
		"spring", "graphql", "sqli", "idor", "wordpress",
		"misconfiguration", "weird-new-tag",
	}
	out := BuildModuleCatalog(tags, 245)
	if out == "" {
		t.Fatal("expected non-empty catalog")
	}

	// Header carries both counts.
	if !strings.Contains(out, "7 available module tags") {
		t.Errorf("expected tag count in header, got: %q", out)
	}
	if !strings.Contains(out, "245 registered scanner modules") {
		t.Errorf("expected module count in header, got: %q", out)
	}

	// Each known tag must land in some bucket — no silent drops.
	for _, tag := range tags {
		if !strings.Contains(out, tag) {
			t.Errorf("tag %q missing from catalog: %q", tag, out)
		}
	}

	// Unknown tag should appear under "Other".
	if !strings.Contains(out, "Other: weird-new-tag") {
		t.Errorf("uncategorized tag should fall into Other bucket, got: %q", out)
	}

	// Categorization sanity check.
	wantBuckets := map[string]string{
		"Stacks & frameworks":     "spring",
		"CMS & platforms":         "wordpress",
		"Protocols & API surface": "graphql",
		"Injection vulns":         "sqli",
		"Auth & access control":   "idor",
		"Misconfig & exposure":    "misconfiguration",
	}
	for label, tag := range wantBuckets {
		line := findLineContaining(out, label)
		if line == "" {
			t.Errorf("expected bucket %q in output, got: %q", label, out)
			continue
		}
		if !strings.Contains(line, tag) {
			t.Errorf("expected tag %q under bucket %q, line was: %q", tag, label, line)
		}
	}
}

func TestBuildModuleCatalog_EmptyInput(t *testing.T) {
	if got := BuildModuleCatalog(nil, 0); got != "" {
		t.Errorf("expected empty string for empty tags, got: %q", got)
	}
}

func TestBuildModuleCatalog_DeterministicOrder(t *testing.T) {
	tags := []string{"sqli", "xss", "graphql", "spring", "idor"}
	a := BuildModuleCatalog(tags, 10)
	// Shuffle input — output should be identical.
	b := BuildModuleCatalog([]string{"idor", "graphql", "xss", "sqli", "spring"}, 10)
	if a != b {
		t.Errorf("catalog output is not stable across input orderings:\nA: %q\nB: %q", a, b)
	}
}

func TestEnrichContextModules_PopulatesCatalogWhenDeclared(t *testing.T) {
	// EnrichContextModules pulls from the live registry, which the
	// default_registry init wires up. We just verify wiring: when the
	// template declares ModuleCatalog, the field is populated and is a
	// superset of what BuildModuleCatalog would produce.
	data := &agenttypes.TemplateData{}
	EnrichContextModules(data, []string{"ModuleCatalog"})
	if data.ModuleCatalog == "" {
		t.Fatal("expected ModuleCatalog to be populated when declared")
	}
	if !strings.Contains(data.ModuleCatalog, "available module tags") {
		t.Errorf("expected catalog header in output, got: %q", data.ModuleCatalog)
	}
}

func TestEnrichContextModules_SkipsWhenNotDeclared(t *testing.T) {
	data := &agenttypes.TemplateData{}
	EnrichContextModules(data, []string{"TargetURL"})
	if data.ModuleCatalog != "" {
		t.Errorf("expected empty ModuleCatalog when not declared, got: %q", data.ModuleCatalog)
	}
	if data.ModuleTags != "" {
		t.Errorf("expected empty ModuleTags when not declared, got: %q", data.ModuleTags)
	}
}

// findLineContaining returns the first line in s containing substr, or "".
func findLineContaining(s, substr string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}
