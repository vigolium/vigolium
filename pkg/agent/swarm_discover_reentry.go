package agent

import (
	"context"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// normalizeURLPath strips the query string and the trailing slash so
// "/api/users?id=1" and "/api/users/" both collapse to "/api/users".
// Distinct from pathToPrefix, which buckets to 2-segment prefixes.
func normalizeURLPath(p string) string {
	p = strings.SplitN(p, "?", 2)[0]
	return strings.TrimRight(p, "/")
}

func extractPlanReferencedPaths(plan *SwarmPlan) []string {
	if plan == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(text string) {
		for _, match := range planPathRE.FindAllString(text, -1) {
			path := normalizeURLPath(match)
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, path)
		}
	}
	for _, fa := range plan.FocusAreas {
		add(fa)
	}
	if plan.Notes != "" {
		add(plan.Notes)
	}
	return out
}

func filterUntestedPaths(paths []string, records []*httpmsg.HttpRequestResponse) []string {
	if len(paths) == 0 || len(records) == 0 {
		return paths
	}
	covered := map[string]bool{}
	for _, rr := range records {
		if rr == nil || rr.Request() == nil {
			continue
		}
		covered[normalizeURLPath(rr.Request().Path())] = true
	}
	out := paths[:0:0]
	for _, p := range paths {
		if !covered[p] {
			out = append(out, p)
		}
	}
	return out
}

// resolvePathsToURLs joins paths against targetURL's scheme+host. Capped
// at maxResolved.
func resolvePathsToURLs(targetURL string, paths []string, maxResolved int) []string {
	if targetURL == "" || len(paths) == 0 {
		return nil
	}
	base, err := url.Parse(targetURL)
	if err != nil || base.Host == "" {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		u := &url.URL{
			Scheme: base.Scheme,
			Host:   base.Host,
			Path:   p,
		}
		out = append(out, u.String())
		if maxResolved > 0 && len(out) >= maxResolved {
			break
		}
	}
	return out
}

// discoverReentryProbe GETs each URL through the swarm probe pool and
// returns the records that came back with a response. DB persistence
// is the caller's job.
func discoverReentryProbe(ctx context.Context, urls []string, pc ProbeConfig) []*httpmsg.HttpRequestResponse {
	if len(urls) == 0 {
		return nil
	}
	candidates := make([]*httpmsg.HttpRequestResponse, 0, len(urls))
	for _, u := range urls {
		req, err := httpmsg.HttpRequestFromURL(u)
		if err != nil {
			zap.L().Debug("discoverReentryProbe: failed to build request", zap.String("url", u), zap.Error(err))
			continue
		}
		candidates = append(candidates, httpmsg.NewHttpRequestResponse(req, nil))
	}
	probeRecordsWithConfig(ctx, candidates, pc)
	out := candidates[:0:0]
	for _, rr := range candidates {
		if rr != nil && rr.HasResponse() {
			out = append(out, rr)
		}
	}
	return out
}
