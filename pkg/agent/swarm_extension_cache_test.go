package agent

import (
	"testing"
)

func TestExtensionCacheKey_StableAcrossOrder(t *testing.T) {
	planA := &SwarmPlan{
		FocusAreas: []string{"SQLi in /api/users", "XSS in /api/products"},
		ModuleTags: []string{"sqli", "xss"},
		ModuleIDs:  []string{"sqli-error-based", "xss-dom"},
	}
	planB := &SwarmPlan{
		// Same content, different order — should produce identical key.
		FocusAreas: []string{"XSS in /api/products", "SQLi in /api/users"},
		ModuleTags: []string{"xss", "sqli"},
		ModuleIDs:  []string{"xss-dom", "sqli-error-based"},
	}
	a := extensionCacheKey("https://target.test", planA)
	b := extensionCacheKey("https://target.test", planB)
	if a == "" || a != b {
		t.Errorf("expected stable cache key across input ordering: a=%q b=%q", a, b)
	}
}

func TestExtensionCacheKey_DistinctOnContentChange(t *testing.T) {
	plan := &SwarmPlan{
		FocusAreas: []string{"SQLi in /api/users"},
		ModuleTags: []string{"sqli"},
	}
	a := extensionCacheKey("https://target.test", plan)
	plan.ModuleTags = append(plan.ModuleTags, "xss")
	b := extensionCacheKey("https://target.test", plan)
	if a == b {
		t.Error("expected distinct cache keys when plan content changes")
	}
}

func TestExtensionCacheKey_DistinctPerHost(t *testing.T) {
	plan := &SwarmPlan{
		FocusAreas: []string{"SQLi in /api/users"},
	}
	a := extensionCacheKey("https://a.test", plan)
	b := extensionCacheKey("https://b.test", plan)
	if a == b {
		t.Error("expected distinct cache keys per target host")
	}
}

func TestExtensionCacheKey_NilOrEmpty(t *testing.T) {
	if got := extensionCacheKey("", nil); got != "" {
		t.Errorf("nil plan should yield empty key, got %q", got)
	}
	if got := extensionCacheKey("", &SwarmPlan{}); got != "" {
		t.Errorf("empty plan with empty target should yield empty key, got %q", got)
	}
}

func TestSortedCopy_DoesNotMutateInput(t *testing.T) {
	in := []string{"c", "a", "b"}
	out := sortedCopy(in)
	if in[0] != "c" {
		t.Errorf("sortedCopy mutated input slice: %+v", in)
	}
	if out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Errorf("sortedCopy didn't sort: %+v", out)
	}
}
