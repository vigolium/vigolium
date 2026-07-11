package discovery

import (
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/tag"
	"go.uber.org/zap"
)

// JS-bundle sweep
//
// On monolith / server-rendered apps, application JavaScript and its sibling
// config/data files live under hand-written, never-content-hashed names
// (main.js, admin.js, config.js, settings.json, …) that are frequently NOT
// linked from the HTML. This sweep guesses those names — each tried as both
// .js and .json — across root, the start directory and the app's observed JS
// directories, confirms the real ones against the soft-404 baseline, and feeds
// them to the JS-fetch pipeline (jstangle + linkfinder path extraction, recorded
// as http_records so secret-scanning and later phases see their bodies).
//
// It is skipped on JS-shell SPAs (Next.js/React/Angular/Vue/Svelte): their
// bundles are content-hashed (main.a1b2c3.js) so guessing main.js misses, and
// the real bundles are already linked and harvested by the normal JS pipeline.

const (
	// maxObservedJSDirs caps the app-hosted JS directories remembered from the
	// start page (bounds both memory and the sweep's request fan-out).
	maxObservedJSDirs = 32
	// maxJSBundleBases caps how many base directories the sweep probes.
	maxJSBundleBases = 6
	// maxJSBundleProbes is a hard ceiling on total requests the sweep issues
	// (across all directories and both extensions).
	maxJSBundleProbes = 300
	// jsBundleProbeWorkers bounds in-flight probe requests per directory.
	jsBundleProbeWorkers = 8
	// jsBundleNonceName is an improbable base name used for the per-(directory,
	// extension) wildcard guard: if <nonce>.<ext> resolves to a real-looking
	// asset, that directory catch-alls the extension and no hit in it can be
	// trusted.
	jsBundleNonceName = "vig0lium-no-such-bundle-9q7w3z"
)

// jsBundleExtensions are the extensions each curated name is probed under. Both
// reuse the same name list: .js for bundles, .json for sibling config/data.
var jsBundleExtensions = []string{"js", "json"}

// jsBundleModernAppMatcher fingerprints JS-shell SPA frameworks on the start
// page. It is stateless after construction, so a single shared instance is safe.
var jsBundleModernAppMatcher = tag.NewModernAppMatcher()

// captureStartURLAppShape records, from the start URL response, whether the
// landing page is HTML at all and whether it fingerprints as a JS-shell SPA.
// Both gate the JS-bundle sweep. Called once from probeStartURL.
func (e *Engine) captureStartURLAppShape(path, contentType string, body []byte) {
	e.startURLIsHTML = isHTMLContentType(contentType)
	e.startURLIsModernApp = looksLikeModernAppLanding(body, contentType, path)
}

// looksLikeModernAppLanding reports whether an HTML landing page fingerprints as
// a modern JS-shell SPA (Next.js/React/Angular/Vue/Svelte). It reuses the shared
// ModernAppMatcher, which already requires an HTML content-type and an
// extensionless / directory-style request path.
func looksLikeModernAppLanding(body []byte, contentType, path string) bool {
	return jsBundleModernAppMatcher.Match(&tag.MatchInput{
		ResponseBody: body,
		MIMEType:     contentType,
		RequestPath:  path,
	})
}

// isHTMLContentType reports whether a Content-Type names an HTML document.
func isHTMLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "html") || strings.Contains(ct, "xhtml")
}

// recordObservedJSDir remembers the directory of an in-scope, app-hosted JS URL
// seen while crawling the start page, so the sweep can probe the app's real JS
// mount points (/js/, /assets/js/, …) in addition to root + the start dir.
//
// Only the start-of-scan sweep reads this set, so once it has run (or if the
// sweep is disabled) recording is a no-op — this is on the concurrent crawl's
// per-JS-URL hot path, so it must not keep taking the lock for a dead set.
func (e *Engine) recordObservedJSDir(u *url.URL) {
	if !e.config.Extensions.JSBundleSweep || e.observedJSDirsConsumed.Load() {
		return
	}
	base := jsDirBase(u)
	if base == "" {
		return
	}
	e.observedJSDirsMu.Lock()
	defer e.observedJSDirsMu.Unlock()
	if e.observedJSDirs == nil {
		e.observedJSDirs = make(map[string]struct{})
	}
	if _, ok := e.observedJSDirs[base]; ok {
		return
	}
	if len(e.observedJSDirs) >= maxObservedJSDirs {
		return
	}
	e.observedJSDirs[base] = struct{}{}
}

// jsDirBase returns the directory base URL (scheme://host/dir/) of u, or "" for
// a relative/incomplete URL. Reuses startURLDirectory for the path-truncation.
func jsDirBase(u *url.URL) string {
	if u == nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return startURLDirectory(u).String()
}

// sweepJSBundles runs the SPA-gated JS-bundle name sweep at start of scan and
// feeds confirmed bundles to jstangle. It returns the number of bundles queued
// (0 when disabled, gated off by the SPA/HTML checks, or nothing confirmed).
func (e *Engine) sweepJSBundles() int {
	if !e.config.Extensions.JSBundleSweep {
		return 0
	}
	// This is the only reader of observedJSDirs; mark it consumed on the way out
	// so the crawl's JS hot path stops recording into a set nothing will read.
	defer e.observedJSDirsConsumed.Store(true)
	if e.httpClient == nil || e.analyzer == nil {
		return 0
	}
	if !e.startURLIsHTML {
		logger.Debug("Skipping JS-bundle sweep (start URL is not an HTML page)")
		return 0
	}
	if e.startURLIsModernApp {
		logger.Info("Skipping JS-bundle sweep (SPA landing page — bundles are content-hashed)")
		return 0
	}

	startURL, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		return 0
	}

	hits := e.collectJSBundleHits(startURL)
	if len(hits) == 0 {
		return 0
	}
	logger.Info("JS-bundle sweep found candidate bundles — queuing for jstangle",
		zap.Int("count", len(hits)))
	e.queueJSFetch(hits, 0)
	return len(hits)
}

// collectJSBundleHits probes the curated names (each as .js and .json) across
// root, the start directory and the app's observed JS directories, returning
// the URLs that confirm as real assets (distinct from the soft-404 baseline).
func (e *Engine) collectJSBundleHits(startURL *url.URL) []*url.URL {
	bases := e.jsBundleProbeBases(startURL)
	if len(bases) == 0 {
		return nil
	}
	names := e.config.Extensions.JSBundleNames
	if len(names) == 0 {
		names = config.DefaultJSBundleNames
	}

	var (
		probes atomic.Int64
		mu     sync.Mutex
		hits   []*url.URL
		capped bool
	)

sweep:
	for _, base := range bases {
		for _, ext := range jsBundleExtensions {
			if e.ctx.Err() != nil {
				break sweep
			}
			if probes.Load() >= maxJSBundleProbes {
				capped = true
				break sweep
			}

			// Wildcard guard: a directory that serves a real-looking asset for an
			// improbable nonce name catch-alls this extension; nothing found in it
			// can be trusted, so skip the (directory, extension) pair entirely.
			probes.Add(1)
			if e.isGenuineAssetResponse(jsBundleProbeURL(base, jsBundleNonceName, ext)) {
				logger.Debug("Skipping JS-bundle directory (serves a catch-all)",
					zap.String("base", base), zap.String("ext", ext))
				continue
			}

			sem := make(chan struct{}, jsBundleProbeWorkers)
			var wg sync.WaitGroup
			for _, name := range names {
				if e.ctx.Err() != nil || probes.Load() >= maxJSBundleProbes {
					capped = true
					break
				}
				probes.Add(1)
				wg.Add(1)
				sem <- struct{}{}
				go func(n, x string) {
					defer wg.Done()
					defer func() { <-sem }()
					if u := e.probeBundleName(base, n, x); u != nil {
						mu.Lock()
						hits = append(hits, u)
						mu.Unlock()
					}
				}(name, ext)
			}
			wg.Wait()
		}
	}
	if capped {
		logger.Info("JS-bundle sweep hit its probe cap; coverage truncated",
			zap.Int("cap", maxJSBundleProbes))
	}
	return hits
}

// jsBundleProbeBases returns the deduped base directories to sweep: root, the
// start directory and the app's observed JS directories, capped.
func (e *Engine) jsBundleProbeBases(startURL *url.URL) []string {
	seen := make(map[string]struct{})
	var bases []string
	add := func(b string) {
		if b == "" {
			return
		}
		if !strings.HasSuffix(b, "/") {
			b += "/"
		}
		if _, ok := seen[b]; ok {
			return
		}
		seen[b] = struct{}{}
		bases = append(bases, b)
	}

	add(startURL.Scheme + "://" + startURL.Host + "/")
	if dir := startURLDirectory(startURL); dir != nil {
		add(dir.String())
	}
	e.observedJSDirsMu.Lock()
	for b := range e.observedJSDirs {
		add(b)
	}
	e.observedJSDirsMu.Unlock()

	if len(bases) > maxJSBundleBases {
		bases = bases[:maxJSBundleBases]
	}
	return bases
}

// jsBundleProbeURL builds <base><name>.<ext>, returning nil on a parse error.
func jsBundleProbeURL(base, name, ext string) *url.URL {
	u, err := url.Parse(base + name + "." + ext)
	if err != nil {
		return nil
	}
	return u
}

// probeBundleName GETs <base><name>.<ext> and returns its URL when it confirms
// as a genuine, in-scope asset (not a soft-404 / catch-all).
func (e *Engine) probeBundleName(base, name, ext string) *url.URL {
	u := jsBundleProbeURL(base, name, ext)
	if u == nil {
		return nil
	}
	if e.spiderScope != nil && !e.spiderScope.IsInScope(u) {
		return nil
	}
	if e.isGenuineAssetResponse(u) {
		return u
	}
	return nil
}

// isGenuineAssetResponse fetches u and reports whether it is a real (non-HTML)
// resource: the soft-404-aware analyzer accepts it AND the response is not HTML
// (an HTML body at a .js/.json path is a routing artifact / soft-404, not a
// real bundle or config file).
func (e *Engine) isGenuineAssetResponse(u *url.URL) bool {
	if u == nil {
		return false
	}
	req, err := pkghttp.NewRequest(u.String()).Headers(e.config.Engine.CustomHeaders).Build()
	if err != nil {
		return false
	}
	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		return false
	}
	defer rc.Close()

	found, err := e.analyzer.Analyze(e.ctx, req, rc)
	if err != nil || !found {
		return false
	}
	resp := rc.Response()
	if resp == nil {
		return false
	}
	// Reject HTML: a .js/.json path returning HTML is a soft-404 / SPA shell,
	// not a real bundle or config file.
	return !isHTMLContentType(resp.Header.Get("Content-Type"))
}
