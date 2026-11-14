package runner

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// kisMaxPrefixesPerHost caps the directory prefixes the known-issue scan
// probes per origin. Every prefix multiplies the path-dependent templates, and
// a crawled app yields hundreds of directories, most holding one page.
const kisMaxPrefixesPerHost = 20

// buildKnownIssueScanTargetSets splits stored paths into origin targets and
// ranked directory-prefix targets: per origin, prefixes holding more distinct
// paths rank first (that is where an app actually lives), shallower before
// deeper on ties, and at most maxPerHost survive. Target strings have no
// trailing slash, matching buildKnownIssueScanTargetsFromPaths.
func buildKnownIssueScanTargetSets(paths []database.PathTarget, maxPerHost int) (origins, prefixes []string) {
	type prefixStat struct {
		target string
		count  int
		depth  int
	}
	seenOrigin := make(map[string]struct{})
	byOrigin := make(map[string]map[string]*prefixStat)
	var originOrder []string
	for _, p := range paths {
		base := buildOriginURL(p.Scheme, p.Hostname, p.Port)
		if _, ok := seenOrigin[base]; !ok {
			seenOrigin[base] = struct{}{}
			originOrder = append(originOrder, base)
			byOrigin[base] = make(map[string]*prefixStat)
		}
		dir := directoryOf(p.Path)
		if dir == "/" {
			continue
		}
		target := strings.TrimRight(base+dir, "/")
		st := byOrigin[base][target]
		if st == nil {
			st = &prefixStat{target: target, depth: strings.Count(strings.Trim(dir, "/"), "/") + 1}
			byOrigin[base][target] = st
		}
		st.count++
	}
	for _, base := range originOrder {
		origins = append(origins, strings.TrimRight(base, "/"))
		stats := make([]*prefixStat, 0, len(byOrigin[base]))
		for _, st := range byOrigin[base] {
			stats = append(stats, st)
		}
		sort.Slice(stats, func(i, j int) bool {
			if stats[i].count != stats[j].count {
				return stats[i].count > stats[j].count
			}
			if stats[i].depth != stats[j].depth {
				return stats[i].depth < stats[j].depth
			}
			return stats[i].target < stats[j].target
		})
		if maxPerHost > 0 && len(stats) > maxPerHost {
			stats = stats[:maxPerHost]
		}
		for _, st := range stats {
			prefixes = append(prefixes, st.target)
		}
	}
	return origins, prefixes
}

// directoryOf strips query/fragment and the last segment of a path:
// /api/users/1 -> /api/users/, /api/ -> /api/, "" -> /.
func directoryOf(path string) string {
	if idx := strings.IndexAny(path, "?#"); idx != -1 {
		path = path[:idx]
	}
	if path == "" {
		return "/"
	}
	if !strings.HasSuffix(path, "/") {
		if idx := strings.LastIndex(path, "/"); idx >= 0 {
			path = path[:idx+1]
		}
	}
	return path
}

// techTagGroup ties nuclei product tags to the stack names the fingerprint
// phase reports. Only product-specific tags are listed: excluding a tag is
// only safe when its absence from a host's stack is meaningful.
type techTagGroup struct {
	nucleiTags []string
	aliases    []string
}

var kisTechTagGroups = []techTagGroup{
	{[]string{"wordpress", "wp-plugin", "wp-theme"}, []string{"wordpress"}},
	{[]string{"joomla"}, []string{"joomla"}},
	{[]string{"drupal"}, []string{"drupal"}},
	{[]string{"magento"}, []string{"magento"}},
	{[]string{"jenkins"}, []string{"jenkins"}},
	{[]string{"confluence"}, []string{"confluence"}},
	{[]string{"jira"}, []string{"jira"}},
	{[]string{"gitlab"}, []string{"gitlab"}},
	{[]string{"grafana"}, []string{"grafana"}},
	{[]string{"kibana"}, []string{"kibana"}},
	{[]string{"tomcat"}, []string{"tomcat"}},
	{[]string{"weblogic"}, []string{"weblogic"}},
	{[]string{"jboss"}, []string{"jboss", "wildfly"}},
	{[]string{"coldfusion"}, []string{"coldfusion"}},
	{[]string{"springboot"}, []string{"spring", "spring-boot", "springboot"}},
	{[]string{"laravel"}, []string{"laravel"}},
	{[]string{"django"}, []string{"django"}},
	{[]string{"rails"}, []string{"rails", "ruby-on-rails"}},
	{[]string{"aem"}, []string{"aem", "adobe-experience-manager"}},
	{[]string{"sharepoint"}, []string{"sharepoint"}},
	{[]string{"exchange"}, []string{"exchange", "outlook-web-access", "owa"}},
}

// techExcludeTags returns the product tags no host runs, given each host's
// detected stack names. Nil when any host is unknown (nil entry): narrowing on
// partial knowledge is how coverage disappears silently.
func techExcludeTags(stacks map[string][]string) []string {
	if len(stacks) == 0 {
		return nil
	}
	present := make(map[string]bool)
	for _, names := range stacks {
		if names == nil {
			return nil
		}
		for _, n := range names {
			present[strings.ToLower(strings.TrimSpace(n))] = true
		}
	}
	var out []string
	for _, g := range kisTechTagGroups {
		hit := false
		for _, a := range g.aliases {
			if present[a] {
				hit = true
				break
			}
		}
		if !hit {
			out = append(out, g.nucleiTags...)
		}
	}
	return out
}

// knownIssueScanTechExcludes reads the fingerprint this scan stored for each
// origin and returns the product tags to exclude, or nil when selection is off,
// the operator chose tags explicitly, or any origin has no fingerprint.
func (r *Runner) knownIssueScanTechExcludes(ctx context.Context, scanUUID string, origins []string) []string {
	if r.repository == nil || r.settings == nil || len(origins) == 0 {
		return nil
	}
	kcfg := &r.settings.KnownIssueScan
	if !kcfg.TechSelectionEnabled() || len(kcfg.Tags) > 0 {
		return nil
	}
	reports, err := r.storedFingerprints(ctx, r.options.ProjectUUID, scanUUID)
	if err != nil {
		zap.L().Debug("KnownIssueScan: tech selection unavailable", zap.Error(err))
		return nil
	}
	byEndpoint := make(map[string]*recon.TechStackReport, len(reports))
	for ep, rep := range reports {
		byEndpoint[ep.host+":"+strconv.Itoa(ep.port)] = rep
	}
	stacks := make(map[string][]string, len(origins))
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil {
			return nil
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		rep := byEndpoint[strings.ToLower(u.Hostname())+":"+port]
		if rep == nil {
			stacks[o] = nil
			continue
		}
		names := []string{}
		for _, s := range rep.Stacks {
			names = append(names, s.Name, s.Tag)
		}
		stacks[o] = names
	}
	return techExcludeTags(stacks)
}

var cveIDPattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// nativeDuplicateIndex answers whether a nuclei match repeats a native finding
// of this scan: the same CVE on the same host, or an exposure at the same
// URL path that a native exposure module already filed.
type nativeDuplicateIndex struct {
	cves      map[string]struct{} // host|CVE-ID
	exposures map[string]struct{} // host|path
}

func newNativeDuplicateIndex(findings []*database.Finding) *nativeDuplicateIndex {
	idx := &nativeDuplicateIndex{cves: map[string]struct{}{}, exposures: map[string]struct{}{}}
	for _, f := range findings {
		if f == nil || f.FindingSource == database.FindingSourceKnownIssueScan || f.ModuleType == database.ModuleTypeKnownIssueScan {
			continue
		}
		host := strings.ToLower(f.Hostname)
		for _, m := range cveIDPattern.FindAllString(f.ModuleID+" "+f.ModuleName+" "+strings.Join(f.Tags, " "), -1) {
			idx.cves[host+"|"+strings.ToUpper(m)] = struct{}{}
		}
		if hasExposureTag(f.Tags) {
			if h, p, ok := hostPath(f.URL); ok {
				idx.exposures[h+"|"+p] = struct{}{}
			}
		}
	}
	return idx
}

// duplicate reports whether ev (a nuclei result) repeats a native finding.
func (idx *nativeDuplicateIndex) duplicate(ev *output.ResultEvent) bool {
	if idx == nil || ev == nil {
		return false
	}
	target := ev.Matched
	if target == "" {
		target = ev.URL
	}
	h, p, ok := hostPath(target)
	if !ok {
		return false
	}
	for _, m := range cveIDPattern.FindAllString(ev.ModuleID+" "+ev.Info.Name+" "+strings.Join(ev.Info.Tags, " "), -1) {
		if _, dup := idx.cves[h+"|"+strings.ToUpper(m)]; dup {
			return true
		}
	}
	if hasExposureTag(ev.Info.Tags) {
		if _, dup := idx.exposures[h+"|"+p]; dup {
			return true
		}
	}
	return false
}

func hasExposureTag(tags []string) bool {
	for _, t := range tags {
		switch strings.ToLower(t) {
		case "exposure", "file-exposure", "files", "backup", "config", "disclosure":
			return true
		}
	}
	return false
}

// hostPath returns the lowercase hostname (no port) and the path without query
// or trailing slash.
func hostPath(raw string) (string, string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", "", false
	}
	p := strings.TrimRight(u.Path, "/")
	if p == "" {
		p = "/"
	}
	return strings.ToLower(u.Hostname()), p, true
}

// knownIssueScanDuplicateFilter returns the nuclei Duplicate hook for this
// scan and a counter of suppressed matches, or nil when nothing can be
// compared.
func (r *Runner) knownIssueScanDuplicateFilter(ctx context.Context, scanUUID string) (func(*output.ResultEvent) bool, *atomic.Int64) {
	if r.repository == nil || scanUUID == "" {
		return nil, nil
	}
	// Only what newNativeDuplicateIndex reads: no evidence bodies.
	findings, err := r.repository.FindingsInScan(ctx, r.options.ProjectUUID, scanUUID,
		"id", "finding_source", "module_type", "hostname", "module_id", "module_name", "tags", "url")
	if err != nil || len(findings) == 0 {
		return nil, nil
	}
	idx := newNativeDuplicateIndex(findings)
	if len(idx.cves) == 0 && len(idx.exposures) == 0 {
		return nil, nil
	}
	// nuclei calls the hook from its worker goroutines.
	suppressed := new(atomic.Int64)
	return func(ev *output.ResultEvent) bool {
		if !idx.duplicate(ev) {
			return false
		}
		suppressed.Add(1)
		zap.L().Debug("KnownIssueScan: nuclei match duplicates a native finding; suppressed",
			zap.String("template", ev.ModuleID), zap.String("matched", ev.Matched))
		return true
	}, suppressed
}

// filterKISTargetsByScope drops known-issue targets the scan's scope rejects
// by host or path. Paths come from stored records, which can include
// out-of-scope prefixes (an excluded /admin/ seen by the crawler), and nuclei
// only applies host-level scope on its own. A prefix target names a directory,
// so it is matched as "<path>/". Nil matcher keeps every target.
func filterKISTargetsByScope(m *config.ScopeMatcher, targets []string) (kept []string, dropped int) {
	if m == nil {
		return targets, 0
	}
	for _, t := range targets {
		u, err := url.Parse(t)
		if err != nil {
			dropped++
			continue
		}
		path := strings.TrimRight(u.Path, "/") + "/"
		if m.InScopeTarget(u.Hostname(), path) {
			kept = append(kept, t)
		} else {
			dropped++
		}
	}
	return kept, dropped
}
