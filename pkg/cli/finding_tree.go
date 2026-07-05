package cli

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// urlRef is one affected location plus the finding id that reported it.
type urlRef struct {
	url string
	id  int64
}

// findingPathGroup collapses findings under a path that share the same title
// (severity + module + short + confidence) into a single node, with every
// affected URL listed beneath it — one URL per line so nothing is truncated.
// rep is the first finding of the group; the title/severity/confidence are read
// off it, so there is a single source of truth.
type findingPathGroup struct {
	rep  *database.Finding
	urls []urlRef
}

// treeBranch returns the connector drawn for a node and the bar drawn under it,
// depending on whether the node is the last child of its parent.
func treeBranch(isLast bool) (connector, childBar string) {
	if isLast {
		return "└── ", "    "
	}
	return "├── ", "│   "
}

// displayFindingTree renders findings as a host → path-prefix → finding tree,
// mirroring the layout of `traffic --tree` but with severity, module, confidence
// and matched-at per finding. Repeated titles under a path collapse into one
// node with each affected URL on its own line. Findings without a URL
// (source-audit findings) group under their repo name / source file.
func displayFindingTree(db *database.DB, ctx context.Context, findings []*database.Finding, total int64) error {
	printFindingsSummary(db, ctx, len(findings), total)

	// Group by host, preserving a sorted, deterministic order.
	hostMap := make(map[string][]*database.Finding)
	for _, f := range findings {
		key := findingHostKey(f)
		hostMap[key] = append(hostMap[key], f)
	}
	hostKeys := make([]string, 0, len(hostMap))
	for k := range hostMap {
		hostKeys = append(hostKeys, k)
	}
	sort.Strings(hostKeys)

	for _, hostKey := range hostKeys {
		hostFindings := hostMap[hostKey]
		fmt.Printf("└── %s %s %s\n",
			terminal.BoldCyan(hostKey),
			terminal.BoldMagenta(fmt.Sprintf("(%d findings)", len(hostFindings))),
			findingHostSeverityTag(hostFindings))

		// Group by first path segment (e.g. /api, /admin), like the traffic tree.
		pathMap := make(map[string][]*database.Finding)
		for _, f := range hostFindings {
			p := findingPathPrefix(f)
			pathMap[p] = append(pathMap[p], f)
		}
		pathPrefixes := make([]string, 0, len(pathMap))
		for p := range pathMap {
			pathPrefixes = append(pathPrefixes, p)
		}
		sort.Strings(pathPrefixes)

		for pi, prefix := range pathPrefixes {
			pathConnector, childBar := treeBranch(pi == len(pathPrefixes)-1)
			fmt.Printf("    %s%s\n", pathConnector, prefix)
			printFindingGroups(groupPathFindings(pathMap[prefix]), childBar)
		}
		fmt.Println()
	}
	return nil
}

// printFindingGroups renders each collapsed title group under a path: the group
// leaf, then one line per affected URL (in white) with its reporting id.
func printFindingGroups(groups []*findingPathGroup, childBar string) {
	for gi, g := range groups {
		gConnector, gChildBar := treeBranch(gi == len(groups)-1)
		fmt.Printf("    %s%s%s\n", childBar, gConnector, formatFindingGroupLeaf(g))
		for _, u := range g.urls {
			fmt.Printf("    %s%s    %s %s  %s\n",
				childBar, gChildBar,
				terminal.BoldMagenta("→"),
				terminal.White(u.url),
				terminal.Gray(fmt.Sprintf("#%d", u.id)))
		}
	}
}

// groupPathFindings collapses findings that share a title into one group and
// returns the groups worst-severity first (then module name), each carrying its
// affected URLs de-duplicated and ordered by finding id.
func groupPathFindings(findings []*database.Finding) []*findingPathGroup {
	groupMap := make(map[string]*findingPathGroup)
	var order []string
	for _, f := range findings {
		key := strings.ToLower(f.Severity) + "\x00" + strings.ToLower(f.Confidence) + "\x00" + f.ModuleName + "\x00" + f.ModuleShort
		g := groupMap[key]
		if g == nil {
			g = &findingPathGroup{rep: f}
			groupMap[key] = g
			order = append(order, key)
		}
		locations := f.MatchedAt
		if len(locations) == 0 {
			locations = []string{findingURLValue(f)}
		}
		for _, loc := range locations {
			g.urls = append(g.urls, urlRef{url: loc, id: f.ID})
		}
	}

	groups := make([]*findingPathGroup, 0, len(order))
	for _, k := range order {
		g := groupMap[k]
		g.urls = dedupURLRefs(g.urls)
		groups = append(groups, g)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		ri, rj := severityRank(groups[i].rep.Severity), severityRank(groups[j].rep.Severity)
		if ri != rj {
			return ri > rj
		}
		return groups[i].rep.ModuleName < groups[j].rep.ModuleName
	})
	return groups
}

// dedupURLRefs removes duplicate URLs (keeping the lowest finding id) and orders
// the result by id then URL for stable output.
func dedupURLRefs(refs []urlRef) []urlRef {
	seen := make(map[string]int64, len(refs))
	for _, r := range refs {
		if id, ok := seen[r.url]; !ok || r.id < id {
			seen[r.url] = r.id
		}
	}
	out := make([]urlRef, 0, len(seen))
	for u, id := range seen {
		out = append(out, urlRef{url: u, id: id})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].id != out[j].id {
			return out[i].id < out[j].id
		}
		return out[i].url < out[j].url
	})
	return out
}

// findingHostKey derives the tree's top-level grouping key: the scheme://host of
// the finding's URL, falling back to the bare hostname, a URL parsed from the
// first matched-at entry, then the repo name for source-audit findings.
func findingHostKey(f *database.Finding) string {
	if f.URL != "" {
		if u, err := url.Parse(f.URL); err == nil && u.Host != "" {
			return schemeHost(u)
		}
	}
	if f.Hostname != "" {
		return f.Hostname
	}
	if len(f.MatchedAt) > 0 {
		if u, err := url.Parse(f.MatchedAt[0]); err == nil && u.Host != "" {
			return schemeHost(u)
		}
	}
	if f.RepoName != "" {
		return f.RepoName
	}
	return "(unknown)"
}

// schemeHost renders a parsed URL as scheme://host, defaulting a missing scheme
// to http so the key stays stable.
func schemeHost(u *url.URL) string {
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + u.Host
}

// findingPathPrefix returns the first path segment of a finding's location
// (e.g. "/api"), used to bucket findings under a host. Source-audit findings
// without a URL fall back to their source file.
func findingPathPrefix(f *database.Finding) string {
	raw := f.URL
	if raw == "" && len(f.MatchedAt) > 0 {
		raw = f.MatchedAt[0]
	}
	path := ""
	if raw != "" {
		if u, err := url.Parse(raw); err == nil && u.Path != "" {
			path = u.Path
		} else if strings.HasPrefix(raw, "/") {
			path = raw
		}
	}
	if path == "" && f.SourceFile != "" {
		return f.SourceFile
	}
	if path == "" {
		return "/"
	}
	parts := strings.Split(path, "/")
	if len(parts) > 1 && parts[1] != "" {
		return "/" + parts[1]
	}
	return "/"
}

// formatFindingGroupLeaf renders a collapsed group's title line: a colored
// severity tag, module name, short description (or description fallback) and
// confidence. The finding id(s) live on the per-URL lines below.
func formatFindingGroupLeaf(g *findingPathGroup) string {
	var b strings.Builder
	b.WriteString(colorSeverityTag(g.rep.Severity))
	b.WriteString(" ")
	b.WriteString(terminal.Cyan(g.rep.ModuleName))

	short := g.rep.ModuleShort
	if short == "" {
		short = g.rep.Description
	}
	if short != "" {
		b.WriteString(" — ")
		b.WriteString(terminal.White(clicommon.Truncate(short, 70)))
	}
	if g.rep.Confidence != "" {
		b.WriteString(" (")
		b.WriteString(clicommon.ColorConfidence(g.rep.Confidence))
		b.WriteString(")")
	}
	return b.String()
}

// severityColor returns the terminal color function for a severity label
// (identity for unknown severities). Shared by the tree's severity tag and the
// per-host count so the palette is defined once.
func severityColor(sev string) func(string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return terminal.BoldMagenta
	case "high":
		return terminal.BoldRed
	case "medium":
		return terminal.BoldYellow
	case "low":
		return terminal.Green
	case "suspect":
		return terminal.BoldCyan
	case "info":
		return terminal.BoldBlue
	default:
		return func(s string) string { return s }
	}
}

// colorSeverityTag renders a bracketed, colored severity tag like "[HIGH]".
func colorSeverityTag(sev string) string {
	return severityColor(sev)("[" + strings.ToUpper(sev) + "]")
}

// severityCountBuckets orders the per-host count from most to least severe.
var severityCountBuckets = []struct{ key, label string }{
	{"critical", "C"},
	{"high", "H"},
	{"medium", "M"},
	{"low", "L"},
	{"suspect", "S"},
	{"info", "I"},
}

// findingHostSeverityTag renders a compact per-host severity count like
// "[C:1 H:2 M:1]", omitting zero-count severities.
func findingHostSeverityTag(findings []*database.Finding) string {
	counts := make(map[string]int, len(findings))
	for _, f := range findings {
		counts[strings.ToLower(f.Severity)]++
	}
	var parts []string
	for _, b := range severityCountBuckets {
		if n := counts[b.key]; n > 0 {
			parts = append(parts, severityColor(b.key)(fmt.Sprintf("%s:%d", b.label, n)))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return terminal.Gray("[") + strings.Join(parts, " ") + terminal.Gray("]")
}
