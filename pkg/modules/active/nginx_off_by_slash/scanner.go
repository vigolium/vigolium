package nginx_off_by_slash

import (
	"crypto/md5"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

type Module struct {
	modkit.BaseActiveModule
	ds         dedup.Lazy[dedup.DiskSet]
	injections []string
	suffixes   []string
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds:         dedup.LazyDiskSet("nginx_off_by_slash"),
		injections: []string{"..", "..;", "..%3B"},
		suffixes:   initSuffixes(),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	// Only process GET requests
	var rawHttp []byte
	if ctx.Request().Method() != "GET" {
		rawHttp = infra.SwapToGetMethodRequest(ctx.Request().Raw())
	} else {
		rawHttp = ctx.Request().Raw()
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	// Extract first-level path segment
	segment := firstPathSegment(urlx.Path)
	if segment == "" {
		return results, nil
	}

	// Dedup on host|segment
	checksum := getChecksum(urlx, segment)
	if diskSet != nil && diskSet.IsSeen(checksum) {
		return results, nil
	}

	// Probe the host with a random nonexistent path. Off-by-slash flags are
	// noise on SPAs / wildcard reverse proxies that return the same 2xx shell
	// for every path: their /de../static, /favicon../static, etc. all look
	// successful but resolve to the same index.html.
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)

	// For each injection variant, try each suffix
	for _, injection := range m.injections {
		for _, suffix := range m.suffixes {
			// Build traversal path: /{segment}{injection}/{suffix}
			newPath := "/" + segment + injection + "/" + suffix

			modifiedRaw, err := httpmsg.SetPath(rawHttp, newPath)
			if err != nil {
				continue
			}

			fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
			if err != nil {
				continue
			}
			fuzzedReq = fuzzedReq.WithService(ctx.Service())

			resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}

			statusCode := resp.Response().StatusCode
			contentType := resp.Response().Header.Get("Content-Type")
			// Copy the body before Close: resp.Body().Bytes() aliases the pooled
			// *bytes.Buffer that Close() returns to a process-global pool. `body`
			// (a string) is already a copy, but bodyBytes is later passed to
			// wildcard.MatchesBody after Close, so it must not alias the pool.
			// (Same fix as idor_detection.)
			bodyBytes := append([]byte(nil), resp.Body().Bytes()...)
			body := string(bodyBytes)
			resp.Close()

			// Must be 200 with a non-trivial body
			if statusCode != 200 || len(body) < 50 {
				continue
			}

			// A binary / static-asset response (image, font, media, octet-stream)
			// is the static handler simply serving a file, not an alias traversal
			// we can reason about by body differential — and on a re-optimizing
			// image CDN (Scene7/Akamai) those bytes are not stable between
			// requests, which would defeat the differential/reproduce gates and
			// fabricate a hit. The URL-extension filter (IsValidForInjectionVulns)
			// misses an extensionless image/JS CDN URL; this response Content-Type
			// gate catches it.
			if modkit.IsStaticAssetContentType(contentType) {
				continue
			}

			// Reject responses that look exactly like the wildcard shell —
			// e.g., an SPA index.html served for any path.
			if wildcard.MatchesBody(statusCode, bodyBytes) {
				continue
			}

			// Strict drop-on-fail: re-fetch the same traversal path twice more and
			// require it to keep returning a stable, non-wildcard 200. A one-shot
			// 200 from a transient race / load-balancer flap / caching edge will
			// not reproduce and is dropped.
			if !confirmStableOffBySlash(httpClient, ctx.Service(), modifiedRaw, body, wildcard) {
				continue
			}

			// Differential confirmation — the dominant off-by-slash false positive.
			// A genuine alias traversal serves a SPECIFIC resource from OUTSIDE the
			// alias directory, so its body must differ from the in-alias equivalent
			// path /{segment}/{suffix}. When they match, the backend simply
			// routed/normalized /{segment}{injection}/{suffix} the same as
			// /{segment}/{suffix} — e.g. a prefixed auth middleware / API gateway
			// that returns one generic body (`{"message":"User not logged in"}`,
			// an SPA shell, a 404-as-200) for the entire /{segment} path space. The
			// ".." escaped nothing. Because `segment` is fixed for this request, a
			// suffix-independent generic prefix means no other suffix can be a real
			// escape either, so stop probing this request entirely.
			normalizedPath := "/" + segment + "/" + suffix
			if bodySimilarToControl(httpClient, ctx.Service(), rawHttp, normalizedPath, body) {
				return results, nil
			}

			// A real file read is suffix-specific. Confirm the hit body actually
			// depends on the suffix by traversing to a random, non-existent suffix
			// under the same escaped prefix; if that returns the same 2xx body the
			// handler is suffix-invariant (a catch-all under /{segment}{injection}/,
			// not a file read). Drop this hit but keep trying other suffixes — a
			// distinct one may still be a genuine escape under the same parent.
			randomPath := "/" + segment + injection + "/" + modkit.FreshCanary()
			if bodySimilarToControl(httpClient, ctx.Service(), rawHttp, randomPath, body) {
				continue
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.Scheme + "://" + urlx.Host + newPath,
				Request:          string(modifiedRaw),
				Response:         body,
				FuzzingParameter: segment,
				ExtractedResults: []string{injection + "/" + suffix},
				Info: output.Info{
					Description: fmt.Sprintf("Nginx off-by-slash alias traversal via /%s%s/%s", segment, injection, suffix),
				},
			})
			// Stop on first match per injection
			return results, nil
		}
	}

	return results, nil
}

// confirmStableOffBySlash re-issues the traversal request two more times and
// reports whether the off-by-slash hit reproduces: every round must return a 200
// that is not the wildcard shell and whose body stays textually equivalent to the
// first hit (QuickRatio >= UpperRatioBound). It fails OPEN on an inconclusive
// transient error so a real finding is not suppressed by a flaky re-fetch.
func confirmStableOffBySlash(
	httpClient *http.Requester,
	service *httpmsg.Service,
	modifiedRaw []byte,
	firstBody string,
	wildcard *modkit.WildcardEntry,
) bool {
	for i := 0; i < 2; i++ {
		status, body, ok := modkit.ExecuteRaw(httpClient, service, modifiedRaw, http.Options{NoRedirects: true, NoClustering: true})
		if !ok {
			return true
		}
		if status != 200 {
			return false
		}
		if wildcard.MatchesBody(status, []byte(body)) {
			return false
		}
		if !modkit.BodiesSimilar(firstBody, body) {
			return false
		}
	}
	return true
}

// bodySimilarToControl fetches controlPath on the same service and reports
// whether its 2xx response body is textually similar to refBody (the traversal
// hit). It is the core of the off-by-slash differential gate: a control whose
// body matches the hit means the hit was NOT actually produced by the
// traversal. It fails CLOSED toward "not similar" — any transport/parse error
// or a non-2xx control returns false so that a flaky, failed, or 404 control
// can never suppress a real finding; only a genuine matching 2xx body does.
func bodySimilarToControl(
	client *http.Requester,
	service *httpmsg.Service,
	rawHttp []byte,
	controlPath, refBody string,
) bool {
	modified, err := httpmsg.SetPath(rawHttp, controlPath)
	if err != nil {
		return false
	}
	status, body, ok := modkit.ExecuteRaw(client, service, modified, http.Options{NoRedirects: true, NoClustering: true})
	if !ok || status < 200 || status >= 300 {
		return false
	}
	return modkit.BodiesSimilar(refBody, body)
}

// firstPathSegment extracts the first non-empty path segment from a URL path.
// For "/static/js/app.js" it returns "static".
func firstPathSegment(urlPath string) string {
	parts := strings.Split(strings.TrimPrefix(urlPath, "/"), "/")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			return p
		}
	}
	return ""
}

func getChecksum(urlx *urlutil.URL, segment string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(urlx.Host+"|"+segment)))
}

func initSuffixes() []string {
	return []string{
		// Common web directories
		"static", "assets", "uploads", "images", "img", "css", "js",
		"fonts", "media", "files", "content", "resources", "public",
		"dist", "build", "lib", "vendor", "node_modules",
		// Application directories
		"app", "application", "src", "source", "web", "www", "htdocs",
		"html", "templates", "views", "pages", "layouts", "components",
		// Admin / config
		"admin", "administrator", "panel", "dashboard", "config",
		"configuration", "settings", "setup", "install",
		// API
		"api", "api-docs", "swagger", "graphql", "rest", "v1", "v2", "v3",
		// Data / storage
		"data", "database", "db", "backup", "backups", "dump", "export",
		"import", "logs", "log", "tmp", "temp", "cache", "storage",
		// Documentation
		"docs", "doc", "documentation", "help", "wiki", "readme",
		// User content
		"user", "users", "profile", "profiles", "avatar", "avatars",
		"download", "downloads", "upload",
		// Scripts and includes
		"scripts", "includes", "include", "inc", "modules", "plugins",
		"extensions", "addons", "themes", "skins",
		// Common frameworks
		"wp-content", "wp-includes", "wp-admin",
		"sites/default/files", "misc", "core",
		// Misc
		"assets/img", "assets/css", "assets/js", "assets/fonts",
		"static/css", "static/js", "static/img", "static/images",
		"static/media", "static/fonts",
		"public/css", "public/js", "public/images",
		"etc/passwd", "etc/nginx/nginx.conf", "etc/shadow",
		"proc/self/environ", "proc/self/cmdline",
		".git", ".env", "server-status", "server-info",
	}
}
