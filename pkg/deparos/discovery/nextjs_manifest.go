package discovery

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jsscan/linkfinder"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"go.uber.org/zap"
)

var (
	// nextBuildIDRefRe pulls the buildId out of a referenced Next.js manifest
	// path: /_next/static/<buildId>/_buildManifest.js (or _ssgManifest.js). This
	// is the most reliable source — when the HTML links the build manifest, the
	// buildId is right there in the URL.
	nextBuildIDRefRe = regexp.MustCompile(`/_next/static/([^/"'\s]+)/_(?:build|ssg)Manifest\.js`)
	// nextBuildIDDataRe pulls the buildId out of the __NEXT_DATA__ JSON blob,
	// used as a fallback when no manifest is referenced in the markup.
	nextBuildIDDataRe = regexp.MustCompile(`"buildId"\s*:\s*"([^"]+)"`)
)

// nextJSManifestURLs returns the _buildManifest.js and _ssgManifest.js URLs for a
// Next.js page, or nil when the body is not a Next.js page or no buildId can be
// derived. The build manifest enumerates the full page-route table (including
// dynamic routes such as /blog/[slug]); the SSG manifest lists the concrete
// pre-rendered paths. Both are commonly absent from the rendered HTML — the SSG
// manifest in particular is loaded by the client router at runtime rather than as
// a static <script src> — so deriving them directly widens path discovery.
func nextJSManifestURLs(base *url.URL, body []byte) []*url.URL {
	if base == nil || base.Host == "" || len(body) == 0 {
		return nil
	}
	s := string(body)

	buildID := ""
	if m := nextBuildIDRefRe.FindStringSubmatch(s); len(m) > 1 {
		buildID = m[1]
	} else if strings.Contains(s, "__NEXT_DATA__") {
		if m := nextBuildIDDataRe.FindStringSubmatch(s); len(m) > 1 {
			buildID = strings.TrimSpace(m[1])
		}
	}
	if buildID == "" {
		return nil
	}

	scheme := base.Scheme
	if scheme == "" {
		scheme = "https"
	}
	origin := scheme + "://" + base.Host

	out := make([]*url.URL, 0, 2)
	for _, p := range []string{
		fmt.Sprintf("/_next/static/%s/_buildManifest.js", buildID),
		fmt.Sprintf("/_next/static/%s/_ssgManifest.js", buildID),
	} {
		if u, err := url.Parse(origin + p); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// queueNextJSManifests detects a Next.js HTML page and enqueues its build and SSG
// manifests for JS path extraction. Their routes flow through the standard
// JSFetch → linkfinder → observed-path pipeline, so they get probed, recorded as
// http_records, and scanned by later phases. Manifest URLs are de-duplicated
// across pages by the JSFetch layer (seenJSURLs), so this is safe to call for
// every crawled page.
func (e *Engine) queueNextJSManifests(baseURL *url.URL, rc *responsechain.ResponseChain, parentDepth uint16) {
	resp := rc.Response()
	if resp == nil {
		return
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "/html") && !strings.Contains(ct, "/xhtml") {
		return
	}

	urls := nextJSManifestURLs(baseURL, rc.BodyBytes())
	if len(urls) == 0 {
		return
	}

	logger.Debug("Queueing Next.js manifests for route harvest",
		zap.String("url", baseURL.String()),
		zap.Int("count", len(urls)))

	e.queueJSFetch(urls, parentDepth)
}

// appRouteChunkRe matches a Next.js App Router page or route-handler chunk path
// and captures the route segment directory path and the file kind. App Router
// names these chunks after the on-disk route tree, e.g.
// static/chunks/app/dashboard/[id]/page-9f3c.js, so the route is recoverable
// from the path even though App Router routes are absent from _buildManifest.js.
var appRouteChunkRe = regexp.MustCompile(`(?:^|/)app/((?:[^/]+/)*)(page|route)(?:[-.][A-Za-z0-9_]+)?\.js$`)

// deriveAppRouterRoutes derives the addressable route(s) from a Next.js App
// Router page/route-handler chunk path, or nil when the path is not such a chunk
// (or maps to a non-routable private folder). Route groups "(group)" and
// intercepting markers, parallel-route slots "@slot", and the page/route filename
// are stripped; dynamic segments ([id], [...slug]) are normalized to a concrete
// value so the route is directly fetchable.
func deriveAppRouterRoutes(path string) []string {
	m := appRouteChunkRe.FindStringSubmatch(path)
	if m == nil {
		return nil
	}

	var segs []string
	for _, s := range strings.Split(m[1], "/") {
		switch {
		case s == "":
			continue
		case strings.HasPrefix(s, "_"):
			// Private folder — opts its whole subtree out of routing.
			return nil
		case strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")"):
			// Route group / intercepting marker — not part of the URL.
			continue
		case strings.HasPrefix(s, "@"):
			// Parallel-route slot — not part of the URL.
			continue
		default:
			segs = append(segs, s)
		}
	}

	route := "/" + strings.Join(segs, "/")
	if !strings.ContainsAny(route, "[]") {
		return []string{route}
	}
	// Dynamic segments → concrete, fetchable path(s).
	return linkfinder.NormalizePathTemplates(route)
}
