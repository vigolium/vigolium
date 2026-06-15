package crawler

import (
	"context"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// serviceWorkerPrimeTimeout bounds the in-page priming work so a slow or
// unresponsive target cannot stall the crawl. Assets that finish loading before
// the deadline are already captured by the network layer regardless.
const serviceWorkerPrimeTimeout = 90 * time.Second

// serviceWorkerPrimeScript discovers the assets a Progressive Web App's service
// worker (or framework build) would load and fetches them from the page, so the
// browser's network capture records them as spidering traffic.
//
// Why this exists: a modern SPA (Angular, React/CRA, Vue/Nuxt, Next, …) code
// -splits the app into many hashed JS chunks whose filenames are assembled at
// runtime and appear nowhere as literal strings in the markup. On a real visit
// the framework runtime — or a PWA service worker pre-caching the build — fetches
// them because it knows the full list from a manifest the page never links. A
// short headless visit runs neither, so those chunks (and the service workers,
// which often embed API endpoints / cloud config / secrets) are missed.
//
// This script does what they would: it locates the manifests + workers, reads
// their asset lists, and fetches each file. It understands:
//   - Angular     ngsw.json                  (assetGroups + hashTable)
//   - React (CRA) asset-manifest.json        (files + entrypoints)
//   - Nuxt        /_nuxt/builds/latest.json  (→ meta → prerendered routes)
//   - Any PWA     Workbox precache list      ({url,revision} entries in the SW)
//
// It is bounded: same-origin only, capped at %d fetches, and rate-limited to a
// small concurrency so a precache-everything manifest cannot flood the target.
//
// It only follows resources the live app actually registers or declares — an
// installed worker (navigator.serviceWorker.getRegistrations, which sees workers
// a static-HTML scan cannot, e.g. ones registered from a bundled JS file), a
// <link rel=manifest>, an inline serviceWorker.register('...') target — and the
// asset lists those declared manifests enumerate. It deliberately does NOT guess
// well-known PWA/framework filenames: that is path brute-forcing, the discovery
// phase's job, already done there with soft-404 gating
// (discovery.spaManifestCandidateURLs). Guessing here too only duplicated that
// work and, on a SPA catch-all host (200 + index shell for any path), recorded a
// soft-404 per guess.
const serviceWorkerPrimeScript = `(async () => {
  const origin = location.origin;
  const MAX = %d;
  const seen = new Set();
  const fetched = new Set();
  const queue = [];
  const add = (raw) => {
    if (!raw || typeof raw !== 'string') return;
    let abs;
    try { abs = new URL(raw, document.baseURI); } catch (e) { return; }
    if (abs.origin !== origin) return;          // same-origin only
    abs.hash = '';
    const href = abs.href;
    if (seen.has(href)) return;
    seen.add(href);
    queue.push(href);
  };

  const fetchOpts = { credentials: 'include', redirect: 'follow' };
  const fetchText = async (u) => {
    fetched.add(u);
    try { const r = await fetch(u, fetchOpts); if (!r.ok) return null; return await r.text(); }
    catch (e) { return null; }
  };

  // 1) Any service worker already registered for this page. The live browser has
  //    run the page's scripts, so getRegistrations() reports the worker the app
  //    actually installed — including one registered from a bundled JS file, which
  //    a static-HTML scan never sees. This is the browser-native source.
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
      const regs = await navigator.serviceWorker.getRegistrations();
      for (const r of regs) {
        for (const w of [r.active, r.installing, r.waiting]) {
          if (w && w.scriptURL) add(w.scriptURL);
        }
      }
    }
  } catch (e) {}

  // 2) Resources the document explicitly declares: a <link rel=manifest> /
  //    <link rel=serviceworker> href, and the URL passed to an inline
  //    serviceWorker.register('...') call (caught even when registration has not
  //    yet resolved, so getRegistrations above missed it). These are read off the
  //    page, never guessed, so a site that declares none emits no request.
  try {
    document.querySelectorAll('link[rel~="manifest"],link[rel="serviceworker"]')
      .forEach(l => { const h = l.getAttribute('href'); if (h) add(h); });
  } catch (e) {}
  try {
    const reRegister = /serviceWorker\s*\.\s*register\s*\(\s*['"]([^'"]+)['"]/ig;
    for (const s of document.scripts) {
      if (!s.textContent) continue;
      reRegister.lastIndex = 0;
      let m;
      while ((m = reRegister.exec(s.textContent)) !== null) add(m[1]);
    }
  } catch (e) {}

  // Guessing well-known PWA/framework filenames is intentionally NOT done here —
  // that is path brute-forcing (the discovery phase's job, already done with
  // soft-404 gating). Spidering only follows what the live app registers/declares.

  const isJsonManifest = (u) => /\.json(\?|$)/i.test(u) || /\.webmanifest(\?|$)/i.test(u);
  const swNameRe = /(?:^|\/)(?:sw|service-worker|serviceworker|ngsw-worker|firebase-messaging-sw|combined-sw|safety-worker|worker-basic\.min)\.js(?:\?|$)/i;
  const isSW = (u) => swNameRe.test(u) || /workbox/i.test(u);

  // 3) Read JSON manifests for their asset lists. Multi-round because one
  //    manifest can point at another (Nuxt latest.json -> meta -> routes).
  const parsed = new Set();
  for (let round = 0; round < 4; round++) {
    const pending = queue.filter(u => isJsonManifest(u) && !parsed.has(u));
    if (pending.length === 0) break;
    for (const m of pending) {
      parsed.add(m);
      const txt = await fetchText(m);
      if (!txt) continue;
      let data; try { data = JSON.parse(txt); } catch (e) { continue; }
      if (!data || typeof data !== 'object') continue;
      // Angular ngsw.json
      if (Array.isArray(data.assetGroups)) {
        for (const g of data.assetGroups) { if (g && Array.isArray(g.urls)) g.urls.forEach(add); }
      }
      if (data.hashTable && typeof data.hashTable === 'object') Object.keys(data.hashTable).forEach(add);
      // React CRA asset-manifest.json
      if (data.files && typeof data.files === 'object') {
        Object.values(data.files).forEach(v => { if (typeof v === 'string') add(v); });
      }
      if (Array.isArray(data.entrypoints)) data.entrypoints.forEach(add);
      // Nuxt latest.json -> meta manifest
      if (typeof data.id === 'string' && /\/_nuxt\/builds\/latest\.json/i.test(m) && /^[A-Za-z0-9_-]+$/.test(data.id)) {
        add('/_nuxt/builds/meta/' + data.id + '.json');
      }
      // Nuxt meta -> prerendered routes
      if (Array.isArray(data.prerendered)) data.prerendered.forEach(add);
    }
  }

  // 4) Workbox precache lists embedded in service workers. Each entry is an
  //    object carrying a url + revision; that shape is unique to a precache list.
  const wbRe = /\{\s*["']?url["']?\s*:\s*["']([^"']+)["']\s*,\s*["']?revision["']?\s*:\s*(?:null|"[^"]*"|'[^']*')\s*\}|\{\s*["']?revision["']?\s*:\s*(?:null|"[^"]*"|'[^']*')\s*,\s*["']?url["']?\s*:\s*["']([^"']+)["']\s*\}/g;
  for (const s of queue.filter(isSW)) {
    const txt = await fetchText(s);
    if (!txt || txt.indexOf('revision') === -1) continue;
    wbRe.lastIndex = 0;
    let mm;
    while ((mm = wbRe.exec(txt)) !== null) add(mm[1] || mm[2]);
  }

  // 5) Fetch every queued asset not already fetched (bounded + rate-limited) so
  //    each gets recorded.
  const targets = queue.filter(u => !fetched.has(u)).slice(0, MAX);
  let idx = 0, ok = 0;
  const worker = async () => {
    while (idx < targets.length) {
      const u = targets[idx++];
      try {
        const r = await fetch(u, fetchOpts);
        try { await r.arrayBuffer(); } catch (e) {}  // drain so the load finishes
        ok++;
      } catch (e) {}
    }
  };
  await Promise.all(Array.from({length: Math.min(8, targets.length)}, worker));
  return ok;
})()`

// primeServiceWorkerAssets runs the service-worker asset priming script on the
// page, fetching the assets a PWA service worker / framework build would load so
// the network capture records them. It is best-effort: any failure (eval error,
// timeout, context cancellation) is logged at debug and the crawl continues —
// the assets that did load are still captured.
func (c *Crawler) primeServiceWorkerAssets(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || !c.config.ServiceWorkerPriming {
		return
	}

	maxAssets := c.config.ServiceWorkerMaxAssets
	if maxAssets <= 0 {
		maxAssets = 600
	}
	script := fmt.Sprintf(serviceWorkerPrimeScript, maxAssets)

	// Run the eval on a goroutine so crawl-context cancellation can return
	// promptly even if CDP is slow to respond; the eval itself is bounded by
	// serviceWorkerPrimeTimeout.
	done := make(chan struct{})
	var primed interface{}
	var evalErr error
	go func() {
		defer close(done)
		primed, evalErr = page.EvalAwait(script, serviceWorkerPrimeTimeout)
	}()

	select {
	case <-ctx.Done():
		zap.L().Debug("Service-worker priming aborted by context")
		return
	case <-done:
	}

	if evalErr != nil {
		zap.L().Debug("Service-worker priming failed", zap.Error(evalErr))
		return
	}
	zap.L().Debug("Service-worker assets primed", zap.Any("fetched", primed))
}
