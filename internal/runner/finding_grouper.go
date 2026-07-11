package runner

import (
	"fmt"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// liveFindingGroup tracks one collapsed group during a phase: the representative
// value and host plus a running occurrence count and a capped sample of the URLs
// the value spanned (used for the end-of-phase rollup line).
type liveFindingGroup struct {
	moduleID string
	sev      severity.Severity
	value    string
	host     string
	sample   []string
	count    int
}

// findingGrouper collapses live console output for findings that repeat the same
// extracted value (one leaked secret seen on many URLs) so a phase emits one line
// per unique value instead of one per URL. It also owns the grouped severity
// tallies used for the phase summary. Safe for concurrent OnResult callbacks.
type findingGrouper struct {
	mu            sync.Mutex
	cfg           config.FindingGroupingConfig
	tagSet        map[string]struct{}
	moduleSet     map[string]struct{} // module IDs grouped by (module, severity[, host]) regardless of value
	ruleSet       map[string]struct{} // module IDs grouped by (module, rule_name, severity[, host])
	bundleSuspect map[string]struct{} // module IDs whose Suspect findings collapse by module
	groups        map[string]*liveFindingGroup
	order         []string
	grouped       map[severity.Severity]int // unique groups + each ungroupable finding
	raw           map[severity.Severity]int // every occurrence (for processed-count bookkeeping)
}

// maxLiveGroupSample bounds how many URLs a live group remembers for its rollup.
const maxLiveGroupSample = 3

func newFindingGrouper(cfg config.FindingGroupingConfig) *findingGrouper {
	return &findingGrouper{
		cfg:           cfg,
		tagSet:        output.NormalizeTagSet(cfg.Tags),
		moduleSet:     output.NormalizeStringSet(cfg.ByModule),
		ruleSet:       output.NormalizeStringSet(cfg.ByRule),
		bundleSuspect: output.NormalizeStringSet(cfg.BundleSuspect),
		groups:        make(map[string]*liveFindingGroup),
		grouped:       make(map[severity.Severity]int),
		raw:           make(map[severity.Severity]int),
	}
}

// observe records a finding and reports whether the caller should render the full
// console line (true for the first occurrence of a group, or any ungroupable
// finding) or suppress it to file-only (false for a repeat). Severity tallies are
// always updated.
func (g *findingGrouper) observe(result *output.ResultEvent) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	sev := result.Info.Severity
	g.raw[sev]++

	key, value, ok := g.groupKey(result)
	if !ok {
		g.grouped[sev]++ // ungroupable — counts individually and always shows
		return true
	}

	grp, seen := g.groups[key]
	if !seen {
		grp = &liveFindingGroup{moduleID: result.ModuleID, sev: sev, value: value, host: result.Host}
		g.groups[key] = grp
		g.order = append(g.order, key)
		g.grouped[sev]++
	}
	grp.count++
	if u := output.MatchedURL(result); u != "" && len(grp.sample) < maxLiveGroupSample {
		grp.sample = appendUniqueStr(grp.sample, u)
	}
	return !seen
}

// groupKey returns the grouping key and representative value, or ok=false when the
// finding can't be grouped (grouping disabled, no stable extracted value, or the
// tag gate rejects it).
func (g *findingGrouper) groupKey(result *output.ResultEvent) (key, value string, ok bool) {
	if !g.cfg.Enabled {
		return "", "", false
	}
	value = output.NormalizedValueKey(result.ExtractedResults)
	moduleKey, keyValue, groupable := output.GroupingBranch(
		result.ModuleID, result.Info.Name, value, result.Info.Severity.String(), result.Info.Tags,
		g.moduleSet, g.ruleSet, g.bundleSuspect, g.tagSet)
	if !groupable {
		return "", "", false
	}
	key = output.GroupingKey(moduleKey, result.Info.Severity.String(), keyValue, result.Host, g.cfg.PerHost)
	return key, value, true
}

// summaryCounts returns the grouped severity tallies (repeats of the same value
// count once) for the phase summary line.
func (g *findingGrouper) summaryCounts() map[severity.Severity]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[severity.Severity]int, len(g.grouped))
	for s, c := range g.grouped {
		out[s] = c
	}
	return out
}

// rawTotal returns the number of findings actually emitted (and written to the
// DB) this phase, before grouping — used for progress bookkeeping.
func (g *findingGrouper) rawTotal() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	total := 0
	for _, c := range g.raw {
		total += c
	}
	return total
}

// rollupLines returns one muted line per collapsed group (count > 1) noting how
// many URLs the value spanned, capped so the summary stays readable.
func (g *findingGrouper) rollupLines() []string {
	g.mu.Lock()
	defer g.mu.Unlock()

	const maxLines = 20
	var lines []string
	collapsed := 0
	for _, key := range g.order {
		grp := g.groups[key]
		if grp.count <= 1 {
			continue
		}
		collapsed++
		if len(lines) < maxLines {
			lines = append(lines, formatValueGroupRollup(grp))
		}
	}
	if collapsed > len(lines) {
		lines = append(lines, terminal.Gray(fmt.Sprintf("  … +%d more grouped value(s)", collapsed-len(lines))))
	}
	return lines
}

func formatValueGroupRollup(grp *liveFindingGroup) string {
	val := terminal.Truncate(grp.value, 60)
	line := fmt.Sprintf("↳ grouped [%s] %s across %d URLs", grp.moduleID, val, grp.count)
	if grp.host != "" {
		line += " (" + grp.host + ")"
	}
	return terminal.Gray(line)
}

// resolveFindingGrouping resolves the effective grouping config for the runner.
// It is keyed under known_issue_scan.group_by_value in config but applies to
// every phase that runs deduplicateFindings (KnownIssueScan and DynamicAssessment
// for the DB pass; KnownIssueScan for the live console). With no settings loaded
// it returns a disabled config so live output is unchanged.
func (r *Runner) resolveFindingGrouping() config.FindingGroupingConfig {
	if r.settings == nil {
		return config.FindingGroupingConfig{}
	}
	return r.settings.KnownIssueScan.ResolveGroupByValue()
}

func appendUniqueStr(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
