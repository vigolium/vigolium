package discovery

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"go.uber.org/zap"
)

// SPA / PWA asset-manifest harvesting.
//
// Modern frontend frameworks code-split the app into many hashed JS chunks whose
// filenames are assembled at runtime (from a webpack chunk-id→hash map, an
// importmap, or the framework router) and so appear nowhere as literal strings
// in the rendered HTML. A real browser fetches them because the framework — or a
// PWA service worker pre-caching the build — knows the full list from a manifest
// the page itself never links. The discovery engine runs neither, so without
// help it misses those chunks (and the service workers, which frequently embed
// API endpoints, cloud config, and secrets).
//
// This mirrors the Next.js route-manifest harvest (nextjs_manifest.go) but for
// the *asset* manifests across frameworks:
//   - Angular     ngsw.json                         (assetGroups + hashTable)
//   - React (CRA) asset-manifest.json               (files + entrypoints)
//   - Nuxt        /_nuxt/builds/latest.json → meta  (prerendered routes)
//   - Any PWA     Workbox precache list in the SW   ({url,revision} entries)
//
// Detected manifests/workers are fetched through the standard JSFetch pipeline;
// the parser for each (dispatched by harvestSPAManifest) fans its asset list
// back through queueJSFetch so every chunk is fetched, recorded as an
// http_record, and scanned by later phases.

var (
	// swRegisterRe pulls the script argument out of a serviceWorker.register
	// call, e.g. navigator.serviceWorker.register('ngsw-worker.js').
	swRegisterRe = regexp.MustCompile(`(?i)serviceWorker\s*\.\s*register\s*\(\s*['"]([^'"]+)['"]`)
	// manifestLinkRe matches a web-app manifest <link>, e.g.
	// <link rel="manifest" href="manifest.webmanifest">.
	manifestLinkRe = regexp.MustCompile(`(?i)<link\b[^>]*\brel\s*=\s*["']?manifest["']?[^>]*>`)
	// hrefAttrRe pulls the href out of a tag.
	hrefAttrRe = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)

	// workboxEntryRe / workboxEntryReRev match a single Workbox precache entry —
	// an object carrying both a url string and a revision (string or null), in
	// either key order. That {url,revision} shape is essentially unique to a
	// Workbox precache list, so it does not false-match other service-worker code.
	workboxEntryRe = regexp.MustCompile(
		`(?i)\{\s*["']?url["']?\s*:\s*["']([^"']+)["']\s*,\s*["']?revision["']?\s*:\s*(?:null|"[^"]*"|'[^']*')\s*\}`)
	workboxEntryReRev = regexp.MustCompile(
		`(?i)\{\s*["']?revision["']?\s*:\s*(?:null|"[^"]*"|'[^']*')\s*,\s*["']?url["']?\s*:\s*["']([^"']+)["']\s*\}`)

	// nuxtBuildIDRe validates a Nuxt build id before it is interpolated into the
	// meta-manifest path, so a hostile latest.json cannot inject a traversal.
	nuxtBuildIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// genericManifestAndSWPaths are root-relative manifest and service-worker
// filenames common across PWAs regardless of framework. They are loaded by the
// browser's service-worker / PWA runtime rather than as <script src> tags, so
// they are absent from the rendered HTML and must be probed by name. asset
// -manifest.json (Create React App) is included here because it 404s harmlessly
// on non-CRA apps and enumerates every hashed chunk on CRA ones.
var genericManifestAndSWPaths = []string{
	"/sw.js",
	"/service-worker.js",
	"/firebase-messaging-sw.js",
	"/combined-sw.js",
	"/safety-worker.js",
	"/worker-basic.min.js",
	"/manifest.webmanifest",
	"/manifest.json",
	"/asset-manifest.json",
}

// urlCollector resolves, scope-filters (same-origin), and de-duplicates URLs
// discovered while harvesting a manifest.
type urlCollector struct {
	base   *url.URL
	origin string
	seen   map[string]struct{}
	out    []*url.URL
}

func newURLCollector(base *url.URL) *urlCollector {
	scheme := base.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &urlCollector{
		base:   base,
		origin: scheme + "://" + base.Host,
		seen:   make(map[string]struct{}),
	}
}

func (c *urlCollector) push(abs *url.URL) {
	if abs == nil || abs.Host != c.base.Host { // same-origin only
		return
	}
	abs.Fragment = ""
	key := abs.String()
	if _, ok := c.seen[key]; ok {
		return
	}
	c.seen[key] = struct{}{}
	c.out = append(c.out, abs)
}

// resolve trims, parses, and resolves a raw reference against the page (so
// relative refs under a base-href sub-path keep their directory). Returns false
// for empty or unparseable input.
func (c *urlCollector) resolve(raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, false
	}
	return c.base.ResolveReference(ref), true
}

// add collects a raw reference.
func (c *urlCollector) add(raw string) {
	if abs, ok := c.resolve(raw); ok {
		c.push(abs)
	}
}

// addPath adds an origin-root-relative path (e.g. "/ngsw.json").
func (c *urlCollector) addPath(p string) {
	u, err := url.Parse(c.origin + p)
	if err != nil {
		return
	}
	c.push(u)
}

// addFetchable collects raw only if it resolves to a fetchable JS/JSON asset,
// avoiding wasted requests for images/fonts/css the JSFetch content-type gate
// (hasJavaScriptExtension / hasJSONExtension) would drop anyway.
func (c *urlCollector) addFetchable(raw string) {
	abs, ok := c.resolve(raw)
	if !ok || (!hasJavaScriptExtension(abs) && !hasJSONExtension(abs)) {
		return
	}
	c.push(abs)
}

// reactMarkers reports React/CRA shell markers in an already-lowercased body.
// Used only to widen the modern-app gate — asset-manifest.json itself is probed
// generically.
func reactMarkers(ls string) bool {
	return strings.Contains(ls, "react-dom") ||
		strings.Contains(ls, "__react_devtools") ||
		strings.Contains(ls, `id="root"`) ||
		strings.Contains(ls, `id='root'`) ||
		strings.Contains(ls, "/static/js/") // CRA bundle directory
}

// nuxtMarkers reports Nuxt (Vue meta-framework) markers in a lowercased body.
func nuxtMarkers(ls string) bool {
	return strings.Contains(ls, "__nuxt__") || strings.Contains(ls, "/_nuxt/")
}

// extraSPAMarkers reports the remaining modern-framework / PWA markers (Next,
// Vue, SvelteKit, service-worker registration) in a lowercased body.
func extraSPAMarkers(ls string) bool {
	for _, m := range []string{
		"__next_data__", "/_next/static/", // Next.js
		"__vue__",                         // Vue
		"__sveltekit", "/_app/immutable/", // SvelteKit
		"serviceworker.register", // any PWA
	} {
		if strings.Contains(ls, m) {
			return true
		}
	}
	return false
}

// looksLikeModernSPA reports whether a page looks like any modern SPA / PWA worth
// probing for asset manifests and service workers. Broad on purpose — the probes
// are bounded, de-duplicated, and 404 harmlessly — but still gated so plain
// server-rendered sites are not probed. The body is lowercased once.
func looksLikeModernSPA(body []byte) bool {
	ls := strings.ToLower(string(body))
	if angularMarkers(ls) || reactMarkers(ls) || nuxtMarkers(ls) || extraSPAMarkers(ls) {
		return true
	}
	return swRegisterRe.Match(body) || manifestLinkRe.Match(body)
}

// spaManifestCandidateURLs returns the manifest and service-worker URLs worth
// probing for a modern SPA / PWA page, or nil when the page is not one. It
// unions the framework-agnostic well-known filenames with any
// serviceWorker.register target and manifest <link href> in the markup, plus
// framework-specific manifests for Angular and Nuxt.
func spaManifestCandidateURLs(base *url.URL, body []byte) []*url.URL {
	if base == nil || base.Host == "" || len(body) == 0 {
		return nil
	}

	// Lowercase the (possibly large) body once and reuse the per-framework
	// verdicts both to gate and to pick framework-specific manifests.
	ls := strings.ToLower(string(body))
	isAngular := angularMarkers(ls)
	isNuxt := nuxtMarkers(ls)
	if !isAngular && !isNuxt && !reactMarkers(ls) && !extraSPAMarkers(ls) &&
		!swRegisterRe.Match(body) && !manifestLinkRe.Match(body) {
		return nil
	}

	c := newURLCollector(base)

	// Framework-agnostic manifests + workers (root-relative).
	for _, p := range genericManifestAndSWPaths {
		c.addPath(p)
	}

	// serviceWorker.register('...') targets referenced in inline script.
	for _, m := range swRegisterRe.FindAllSubmatch(body, -1) {
		if len(m) > 1 {
			c.add(string(m[1]))
		}
	}
	// <link rel="manifest" href="..."> targets.
	for _, tag := range manifestLinkRe.FindAll(body, -1) {
		if hm := hrefAttrRe.FindSubmatch(tag); len(hm) > 1 {
			c.add(string(hm[1]))
		}
	}

	// Framework-specific manifests, gated by their strong markers.
	if isAngular {
		c.addPath("/ngsw.json")
		c.addPath("/ngsw-worker.js")
	}
	if isNuxt {
		c.addPath("/_nuxt/builds/latest.json")
	}

	return c.out
}

// queueSPAAssetManifests detects a modern SPA / PWA HTML page and enqueues its
// manifests and service workers for fetching. The asset lists those manifests
// carry are parsed downstream (harvestSPAManifest, invoked from
// executeJSFetchItem) and fanned back through the JSFetch pipeline. All URLs are
// de-duplicated across pages by the JSFetch layer (seenJSURLs), so this is safe
// to call for every crawled page.
func (e *Engine) queueSPAAssetManifests(baseURL *url.URL, rc *responsechain.ResponseChain, parentDepth uint16) {
	resp := rc.Response()
	if resp == nil {
		return
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "/html") && !strings.Contains(ct, "/xhtml") {
		return
	}

	urls := spaManifestCandidateURLs(baseURL, rc.BodyBytes())
	if len(urls) == 0 {
		return
	}

	logger.Debug("Queueing SPA/PWA asset manifests for harvest",
		zap.String("url", baseURL.String()),
		zap.Int("count", len(urls)))

	e.queueJSFetch(urls, parentDepth)
}

// harvestSPAManifest inspects a fetched manifest / service-worker body and fans
// the assets (or routes) it enumerates back into discovery. It dispatches by URL
// shape so each framework's manifest is parsed by the right reader. Safe to call
// for every JSFetch result; non-manifest bodies match nothing and no-op.
func harvestSPAManifest(jsURL *url.URL, body []byte, cb *Callbacks) {
	if jsURL == nil || len(body) == 0 || len(body) > maxJSSize {
		return
	}

	switch {
	case isNgswManifest(jsURL):
		queueAssets(cb, parseNgswManifestAssets(jsURL, body), "ngsw.json", jsURL)
	case isCRAAssetManifest(jsURL):
		queueAssets(cb, parseCRAAssetManifest(jsURL, body), "asset-manifest.json", jsURL)
	case isNuxtLatest(jsURL):
		queueAssets(cb, parseNuxtLatest(jsURL, body), "nuxt latest.json", jsURL)
	case isNuxtMeta(jsURL):
		// Nuxt meta enumerates pre-rendered *routes* (HTML), not JS assets — feed
		// them to the observed-path pipeline so they are probed and recorded.
		if cb.AddObservedPath != nil {
			for _, p := range parseNuxtPrerendered(body) {
				cb.AddObservedPath(p)
			}
		}
	case looksLikeServiceWorkerURL(jsURL) && hasWorkboxSignature(body):
		queueAssets(cb, parseWorkboxPrecache(jsURL, body), "workbox precache", jsURL)
	}
}

// queueAssets fans a parsed asset list back through the JSFetch pipeline.
func queueAssets(cb *Callbacks, assets []*url.URL, kind string, src *url.URL) {
	if cb.QueueJSFetch == nil || len(assets) == 0 {
		return
	}
	logger.Debug("Fanning out SPA manifest assets",
		zap.String("kind", kind),
		zap.String("url", src.String()),
		zap.Int("count", len(assets)))
	cb.QueueJSFetch(assets)
}

// isCRAAssetManifest reports whether a URL points at a Create React App
// asset-manifest.json.
func isCRAAssetManifest(u *url.URL) bool {
	return u != nil && strings.HasSuffix(strings.ToLower(u.Path), "asset-manifest.json")
}

// isNuxtLatest reports whether a URL points at the Nuxt app-manifest pointer
// (/_nuxt/builds/latest.json).
func isNuxtLatest(u *url.URL) bool {
	return u != nil && strings.HasSuffix(strings.ToLower(u.Path), "/_nuxt/builds/latest.json")
}

// isNuxtMeta reports whether a URL points at a Nuxt build meta manifest
// (/_nuxt/builds/meta/<id>.json).
func isNuxtMeta(u *url.URL) bool {
	if u == nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.Contains(p, "/_nuxt/builds/meta/") && strings.HasSuffix(p, ".json")
}

// looksLikeServiceWorkerURL reports whether a URL's filename looks like a service
// worker (so its body is worth scanning for a Workbox precache list).
func looksLikeServiceWorkerURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	p := strings.ToLower(u.Path)
	if !strings.HasSuffix(p, ".js") {
		return false
	}
	name := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		name = p[i+1:]
	}
	return strings.Contains(name, "service-worker") ||
		strings.Contains(name, "serviceworker") ||
		strings.Contains(name, "worker") ||
		strings.Contains(name, "workbox") ||
		name == "sw.js" ||
		strings.HasSuffix(name, "-sw.js")
}

// hasWorkboxSignature reports whether a service-worker body contains a Workbox
// precache list. Every precache entry carries a "revision", so its presence is a
// cheap byte-level gate before running the entry regexes — avoiding a full
// string copy of a body that may be tens of MB.
func hasWorkboxSignature(body []byte) bool {
	return bytes.Contains(body, []byte("revision"))
}

// craAssetManifest is the subset of Create React App's asset-manifest.json we
// read. files maps logical names to emitted asset URLs; entrypoints lists the
// initial bundles. Together they enumerate every hashed chunk.
type craAssetManifest struct {
	Files       map[string]string `json:"files"`
	Entrypoints []string          `json:"entrypoints"`
}

// parseCRAAssetManifest parses a CRA asset-manifest.json and returns every
// same-origin fetchable asset URL it lists.
func parseCRAAssetManifest(base *url.URL, body []byte) []*url.URL {
	if base == nil || base.Host == "" || len(body) == 0 {
		return nil
	}
	var m craAssetManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	c := newURLCollector(base)
	for _, v := range m.Files {
		c.addFetchable(v)
	}
	for _, e := range m.Entrypoints {
		c.addFetchable(e)
	}
	return c.out
}

// parseNuxtLatest parses a Nuxt /_nuxt/builds/latest.json and returns the URL of
// the build's meta manifest, derived from its id. The meta manifest holds the
// pre-rendered route list, which parseNuxtPrerendered later harvests.
func parseNuxtLatest(base *url.URL, body []byte) []*url.URL {
	if base == nil || base.Host == "" || len(body) == 0 {
		return nil
	}
	var m struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	id := strings.TrimSpace(m.ID)
	if id == "" || !nuxtBuildIDRe.MatchString(id) {
		return nil
	}
	c := newURLCollector(base)
	c.addPath("/_nuxt/builds/meta/" + id + ".json")
	return c.out
}

// parseNuxtPrerendered parses a Nuxt build meta manifest and returns its
// pre-rendered route paths (e.g. "/about", "/blog/post-1"), which are absent
// from the SPA shell HTML.
func parseNuxtPrerendered(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var m struct {
		Prerendered []string `json:"prerendered"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	out := make([]string, 0, len(m.Prerendered))
	for _, p := range m.Prerendered {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseWorkboxPrecache extracts the asset URLs from a Workbox precache list
// embedded in a service-worker body. The list is the complete set of assets the
// PWA pre-caches — including hashed chunks that appear nowhere else as literals.
func parseWorkboxPrecache(base *url.URL, body []byte) []*url.URL {
	if base == nil || base.Host == "" || len(body) == 0 {
		return nil
	}
	c := newURLCollector(base)
	for _, re := range []*regexp.Regexp{workboxEntryRe, workboxEntryReRev} {
		for _, m := range re.FindAllSubmatch(body, -1) {
			if len(m) > 1 {
				c.addFetchable(string(m[1]))
			}
		}
	}
	return c.out
}
