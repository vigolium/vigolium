package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func secretEvent(host, url, value string, tags ...string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: "secret-scan",
		Info: output.Info{
			Severity: severity.High,
			Tags:     tags,
		},
		Host:             host,
		Matched:          url,
		URL:              url,
		ExtractedResults: []string{value},
	}
}

func TestFindingGrouper_CollapsesRepeatedValue(t *testing.T) {
	g := newFindingGrouper(config.FindingGroupingConfig{Enabled: true, PerHost: true})

	// Same value across 3 URLs: first shows, next two are suppressed to file-only.
	if !g.observe(secretEvent("www.x.com", "https://www.x.com/a", "AIzaKEY")) {
		t.Error("first occurrence should be shown on screen")
	}
	if g.observe(secretEvent("www.x.com", "https://www.x.com/b", "AIzaKEY")) {
		t.Error("repeat should be suppressed to file-only")
	}
	if g.observe(secretEvent("www.x.com", "https://www.x.com/c", "AIzaKEY")) {
		t.Error("repeat should be suppressed to file-only")
	}

	// A different value is shown.
	if !g.observe(secretEvent("www.x.com", "https://www.x.com/d", "OTHERKEY")) {
		t.Error("distinct value should be shown on screen")
	}

	counts := g.summaryCounts()
	if counts[severity.High] != 2 {
		t.Errorf("expected 2 grouped high findings, got %d", counts[severity.High])
	}
	if g.rawTotal() != 4 {
		t.Errorf("expected rawTotal 4, got %d", g.rawTotal())
	}

	lines := g.rollupLines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 rollup line (the collapsed group), got %d: %v", len(lines), lines)
	}
}

func TestFindingGrouper_PerHostKeepsHostsSeparate(t *testing.T) {
	g := newFindingGrouper(config.FindingGroupingConfig{Enabled: true, PerHost: true})

	if !g.observe(secretEvent("www.x.com", "https://www.x.com/a", "AIzaKEY")) {
		t.Error("first host occurrence should show")
	}
	// Same value, different host — with PerHost it's a new group and shows.
	if !g.observe(secretEvent("api.x.com", "https://api.x.com/a", "AIzaKEY")) {
		t.Error("same value on a different host should show under PerHost")
	}
	if g.summaryCounts()[severity.High] != 2 {
		t.Errorf("expected 2 groups across hosts, got %d", g.summaryCounts()[severity.High])
	}
}

func TestFindingGrouper_TagGate(t *testing.T) {
	g := newFindingGrouper(config.FindingGroupingConfig{Enabled: true, PerHost: true, Tags: []string{"secret"}})

	// Findings lacking the required tag are never grouped — each shows.
	if !g.observe(secretEvent("www.x.com", "https://www.x.com/a", "VAL", "version")) {
		t.Error("untagged finding should show")
	}
	if !g.observe(secretEvent("www.x.com", "https://www.x.com/b", "VAL", "version")) {
		t.Error("untagged repeat should still show (not grouped)")
	}
	if g.summaryCounts()[severity.High] != 2 {
		t.Errorf("expected 2 ungrouped findings, got %d", g.summaryCounts()[severity.High])
	}
}

func TestFindingGrouper_DisabledShowsEverything(t *testing.T) {
	g := newFindingGrouper(config.FindingGroupingConfig{Enabled: false})
	for i := 0; i < 3; i++ {
		if !g.observe(secretEvent("www.x.com", "https://www.x.com/a", "AIzaKEY", "secret")) {
			t.Error("disabled grouper must show every finding")
		}
	}
	if g.summaryCounts()[severity.High] != 3 {
		t.Errorf("expected all 3 counted individually, got %d", g.summaryCounts()[severity.High])
	}
	if len(g.rollupLines()) != 0 {
		t.Errorf("disabled grouper should produce no rollup lines")
	}
}

func sourcemapEvent(host, url, mapName string, sev severity.Severity) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID:         "sourcemap-detect",
		Info:             output.Info{Severity: sev, Tags: []string{"sourcemap"}},
		Host:             host,
		Matched:          url,
		URL:              url,
		ExtractedResults: []string{mapName},
	}
}

func TestFindingGrouper_ByModuleCollapsesDistinctValues(t *testing.T) {
	g := newFindingGrouper(config.FindingGroupingConfig{
		Enabled:  true,
		PerHost:  true,
		ByModule: []string{"sourcemap-detect"},
	})

	// Each JS bundle advertises a DISTINCT .map filename, but the module is
	// by-module, so only the first shows and the rest collapse to file-only.
	if !g.observe(sourcemapEvent("app.x.com", "https://app.x.com/main.111.js", "main.111.js.map", severity.Low)) {
		t.Error("first sourcemap finding should show")
	}
	if g.observe(sourcemapEvent("app.x.com", "https://app.x.com/polyfills.222.js", "polyfills.222.js.map", severity.Low)) {
		t.Error("distinct-value repeat from a by-module module should be suppressed")
	}
	if g.observe(sourcemapEvent("app.x.com", "https://app.x.com/runtime.333.js", "runtime.333.js.map", severity.Low)) {
		t.Error("distinct-value repeat from a by-module module should be suppressed")
	}

	// A higher-severity sourcemap finding is a separate group (severity in key).
	if !g.observe(sourcemapEvent("app.x.com", "https://app.x.com/main.111.js.map", "src/secret.ts", severity.High)) {
		t.Error("different-severity sourcemap finding should show as its own group")
	}
	// Different host stays separate under PerHost.
	if !g.observe(sourcemapEvent("api.x.com", "https://api.x.com/app.444.js", "app.444.js.map", severity.Low)) {
		t.Error("by-module finding on a different host should show under PerHost")
	}

	if c := g.summaryCounts(); c[severity.Low] != 2 || c[severity.High] != 1 {
		t.Errorf("expected 2 low groups + 1 high group, got low=%d high=%d", c[severity.Low], c[severity.High])
	}
}

func ruleSecretEvent(host, url, rule, value string, sev severity.Severity) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: "secret-detect",
		Info: output.Info{
			Name:     rule, // the secret-scan rule name — the per-rule key component
			Severity: sev,
			Tags:     []string{"secret"},
		},
		Host:             host,
		Matched:          url,
		URL:              url,
		ExtractedResults: []string{value},
	}
}

func TestFindingGrouper_ByRuleCollapsesSameRuleKeepsDistinctRules(t *testing.T) {
	g := newFindingGrouper(config.FindingGroupingConfig{
		Enabled: true,
		PerHost: true,
		ByRule:  []string{"secret-detect"},
	})

	// Same rule, distinct chunk-hash values → only the first shows, rest collapse.
	if !g.observe(ruleSecretEvent("lk.x.net", "https://lk.x.net/login", "Looker Client ID", "8b2d330eb01e5f1c4263", severity.High)) {
		t.Error("first Looker finding should show")
	}
	if g.observe(ruleSecretEvent("lk.x.net", "https://lk.x.net/login", "Looker Client ID", "c01fa0008d77f1d4f78c", severity.High)) {
		t.Error("same-rule distinct-value repeat should be suppressed to file-only")
	}
	if g.observe(ruleSecretEvent("lk.x.net", "https://lk.x.net/login", "Looker Client ID", "d03140ea6d9f22ca4538", severity.High)) {
		t.Error("same-rule distinct-value repeat should be suppressed to file-only")
	}

	// A DIFFERENT rule on the same host is its own group and shows.
	if !g.observe(ruleSecretEvent("lk.x.net", "https://lk.x.net/app.js", "AWS Access Key", "AKIAIOSFODNN7EXAMPLE", severity.High)) {
		t.Error("a different secret rule should show as its own group")
	}
	// Same rule on a different host stays separate under PerHost.
	if !g.observe(ruleSecretEvent("other.x.net", "https://other.x.net/login", "Looker Client ID", "aa11bb22cc33dd44ee55", severity.High)) {
		t.Error("same rule on a different host should show under PerHost")
	}

	// 3 groups: Looker@lk, AWS@lk, Looker@other.
	if c := g.summaryCounts()[severity.High]; c != 3 {
		t.Errorf("expected 3 high groups, got %d", c)
	}
}

func TestFindingGrouper_EmptyValueAlwaysShows(t *testing.T) {
	g := newFindingGrouper(config.FindingGroupingConfig{Enabled: true, PerHost: true})
	// No extracted value → ungroupable → every occurrence shows.
	ev := &output.ResultEvent{ModuleID: "header-check", Info: output.Info{Severity: severity.Medium}, Host: "www.x.com", Matched: "https://www.x.com/a"}
	if !g.observe(ev) {
		t.Error("finding with no extracted value should show")
	}
	if !g.observe(ev) {
		t.Error("repeat with no extracted value should still show")
	}
}
