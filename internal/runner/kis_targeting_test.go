package runner

import (
	"fmt"
	"slices"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestBuildKnownIssueScanTargetSets_RankedAndCapped(t *testing.T) {
	var paths []database.PathTarget
	add := func(p string) {
		paths = append(paths, database.PathTarget{Scheme: "https", Hostname: "app.test", Port: 443, Path: p})
	}
	add("/")
	for i := 0; i < 5; i++ {
		add(fmt.Sprintf("/api/v1/item%d", i)) // /api/v1/ x5
	}
	add("/api/x") // /api/ x1
	for i := 0; i < 30; i++ {
		add(fmt.Sprintf("/d%02d/page", i)) // 30 single-path dirs
	}
	origins, prefixes := buildKnownIssueScanTargetSets(paths, 20)
	if !slices.Equal(origins, []string{"https://app.test"}) {
		t.Fatalf("origins = %v", origins)
	}
	if len(prefixes) != 20 {
		t.Fatalf("prefixes = %d, want capped at 20", len(prefixes))
	}
	if prefixes[0] != "https://app.test/api/v1" {
		t.Fatalf("densest prefix must rank first, got %v", prefixes[:3])
	}
	// /api/ (depth 1) beats the depth-1 single-path dirs only lexically; it must
	// be present since ties break shallow-first then lexical.
	if !slices.Contains(prefixes, "https://app.test/api") {
		t.Fatalf("missing /api prefix: %v", prefixes)
	}
}

func TestTechExcludeTags(t *testing.T) {
	if got := techExcludeTags(map[string][]string{"a": {"wordpress"}, "b": nil}); got != nil {
		t.Fatalf("an unknown host must disable narrowing, got %v", got)
	}
	got := techExcludeTags(map[string][]string{"a": {"wordpress", "nginx"}, "b": {"spring-boot"}})
	if slices.Contains(got, "wordpress") || slices.Contains(got, "springboot") {
		t.Fatalf("detected products must stay: %v", got)
	}
	if !slices.Contains(got, "joomla") || !slices.Contains(got, "jenkins") {
		t.Fatalf("absent products must be excluded: %v", got)
	}
}

func TestNativeDuplicateIndex(t *testing.T) {
	idx := newNativeDuplicateIndex([]*database.Finding{
		{Hostname: "app.test", ModuleID: "log4shell_probe", ModuleName: "Log4Shell (CVE-2021-44228)", URL: "https://app.test/"},
		{Hostname: "app.test", ModuleID: "sensitive_file_discovery", URL: "https://app.test/.git/config", Tags: []string{"file-exposure"}},
		{Hostname: "app.test", ModuleID: "CVE-2020-0001", FindingSource: database.FindingSourceKnownIssueScan, URL: "https://app.test/"},
	})
	cases := []struct {
		ev   output.ResultEvent
		want bool
	}{
		{output.ResultEvent{ModuleID: "CVE-2021-44228", Matched: "https://app.test/api?x=1"}, true},
		{output.ResultEvent{ModuleID: "CVE-2021-44228", Matched: "https://other.test/"}, false},
		{output.ResultEvent{ModuleID: "git-config", Matched: "https://app.test/.git/config", Info: output.Info{Tags: []string{"exposure", "config"}}}, true},
		{output.ResultEvent{ModuleID: "git-config", Matched: "https://app.test/.git/config"}, false},
		{output.ResultEvent{ModuleID: "CVE-2020-0001", Matched: "https://app.test/"}, false},
	}
	for i, tc := range cases {
		ev := tc.ev
		if got := idx.duplicate(&ev); got != tc.want {
			t.Errorf("case %d (%s %s): duplicate = %v, want %v", i, ev.ModuleID, ev.Matched, got, tc.want)
		}
	}
}

func TestKnownIssueScanTechSelectionConfig(t *testing.T) {
	c := config.DefaultKnownIssueScanConfig()
	if !c.TechSelectionEnabled() {
		t.Fatal("tech selection defaults to auto")
	}
	c.TechSelection = "off"
	if c.TechSelectionEnabled() {
		t.Fatal("off disables tech selection")
	}
	c.TechSelection = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("an unknown tech_selection value must fail validation")
	}
}
