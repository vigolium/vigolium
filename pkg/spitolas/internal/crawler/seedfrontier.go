package crawler

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg/pathshape"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// seedDiscoverTimeout bounds the whole in-page robots/sitemap fetch-and-parse
// eval. Generous enough for a sitemap index that fans out to child documents,
// short enough that an unresponsive host cannot eat the crawl budget.
const seedDiscoverTimeout = 30 * time.Second

// seedDiscoverScript fetches robots.txt and the sitemap(s) from the page's own
// origin and returns the URLs they declare, as a JSON array.
//
// Both are fetched in-page rather than out-of-band so they travel with the
// browser's cookies and headers and land in the network capture like any other
// request — a host that gates these behind a session still yields them.
//
// robots.txt contributes Allow/Disallow paths and any Sitemap: directives.
// Disallowed paths are the most valuable part of the file: they enumerate what
// the owner deliberately kept out of search indexes, which is routinely the
// admin, export, and internal-tooling surface. Patterns (bearing * or $) are
// rules rather than fetchable locations and are skipped.
//
// Sitemaps contribute <loc> entries, following a <sitemapindex> one level down
// into its child documents. Compressed sitemaps (.xml.gz) are skipped: fetch
// hands back raw bytes and inflating them in-page is not worth the complexity.
//
// __MAX__/__ROBOTS__/__SITEMAP__ are substituted by the caller. Token
// substitution rather than Sprintf, matching the other in-page scripts: these
// bodies carry %-signs of their own.
// No backticks: embedded as a Go raw string.
const seedDiscoverScript = `(async () => {
  const MAX = __MAX__;
  const origin = location.origin;
  const out = [];
  const seen = new Set();
  const add = (raw) => {
    if (!raw || out.length >= MAX) return;
    let u;
    try { u = new URL(String(raw).trim(), origin); } catch (e) { return; }
    if (u.origin !== origin) return;
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
    u.hash = '';
    const href = u.href;
    if (seen.has(href)) return;
    seen.add(href);
    out.push(href);
  };

  const fetchText = async (u) => {
    try {
      const r = await fetch(u, {credentials: 'include', redirect: 'follow'});
      if (!r || !r.ok) return '';
      return await r.text();
    } catch (e) { return ''; }
  };

  const sitemaps = [];
  const wantRobots = __ROBOTS__, wantSitemap = __SITEMAP__;

  if (wantRobots) {
    const txt = await fetchText(origin + '/robots.txt');
    // A server that answers every path with the SPA shell will return HTML here;
    // treating that as a rules file would manufacture junk paths from markup.
    if (txt && !/^\s*</.test(txt)) {
      for (const line of txt.split(/\r?\n/)) {
        const m = /^\s*(allow|disallow|sitemap)\s*:\s*(.+?)\s*$/i.exec(line);
        if (!m) continue;
        const kind = m[1].toLowerCase(), val = m[2];
        if (!val || val === '/') continue;
        if (kind === 'sitemap') { sitemaps.push(val); continue; }
        if (val.indexOf('*') !== -1 || val.indexOf('$') !== -1) continue;
        add(val);
      }
    }
  }

  if (wantSitemap && sitemaps.length === 0) sitemaps.push(origin + '/sitemap.xml');

  const locsOf = (xml) => {
    const locs = [];
    const re = /<loc>\s*([^<\s][^<]*?)\s*<\/loc>/gi;
    let m;
    while ((m = re.exec(xml)) !== null) locs.push(m[1]);
    return locs;
  };
  const isIndex = (xml) => /<sitemapindex[\s>]/i.test(xml);

  const parsed = new Set();
  let queue = sitemaps.filter(s => !/\.gz(\?|$)/i.test(s)).slice(0, 8);
  for (let round = 0; round < 2 && queue.length && out.length < MAX; round++) {
    const next = [];
    for (const sm of queue) {
      if (parsed.has(sm) || out.length >= MAX) continue;
      parsed.add(sm);
      const xml = await fetchText(sm);
      if (!xml) continue;
      const locs = locsOf(xml);
      if (isIndex(xml)) {
        for (const l of locs.slice(0, 8)) { if (!/\.gz(\?|$)/i.test(l)) next.push(l); }
      } else {
        for (const l of locs) add(l);
      }
    }
    queue = next;
  }

  return JSON.stringify(out);
})()`

// seedFrontier fetches robots.txt and the sitemap(s), records everything they
// declare, and promotes a bounded slice of it into the crawl frontier.
//
// Without this the crawl only ever reaches what is reachable by clicking from
// the seed page. Both files exist precisely to name locations that nothing links
// to, so they are the cheapest source of routes an interaction crawl structurally
// cannot find.
//
// The split between the two caps is deliberate. Requesting a URL is cheap, so
// every discovered location is primed and recorded up to SeedMaxURLs, which puts
// it in front of the scanning phases. Rendering one costs a navigation and a
// settle, so only SeedMaxCrawlURLs of them are actually browsed into states —
// enough to pull in link neighbourhoods the seed page never exposed, without
// letting a 50,000-entry sitemap redefine the crawl.
//
// Caller-supplied seeds (Config.ExtraSeeds — client routes the target's own
// JavaScript declares) join the same browse list after the declared ones, under
// their own cap; see selectExtraSeeds.
func (c *Crawler) seedFrontier(ctx context.Context, page *browser.Page) {
	// shouldTerminate rather than a bare ctx check: seeding reads robots.txt and
	// the sitemap from the page's OWN origin — which on a walled start is the
	// identity provider's — and its in-scope filter only screens the RESULTS, by
	// which point both fetches have been sent. Asking the crawler's single
	// "are we done" predicate also covers budget exhaustion, the state cap and a
	// failure streak, none of which wanted another two requests either.
	if page == nil || c.config == nil || c.shouldTerminate(ctx) {
		return
	}
	declared := c.declaredSeedURLs(ctx, page)
	extra := c.extraSeedURLs(page, declared)
	c.crawlSeedURLs(ctx, page, declared, extra)
}

// declaredSeedURLs fetches robots.txt and the sitemap(s) in-page, records every
// in-scope location they declare, and returns the bounded, shape-diverse slice
// worth browsing.
func (c *Crawler) declaredSeedURLs(ctx context.Context, page *browser.Page) []string {
	if !c.config.SeedFromRobots && !c.config.SeedFromSitemap {
		return nil
	}

	script := strings.NewReplacer(
		"__MAX__", strconv.Itoa(c.config.SeedMaxURLs),
		"__ROBOTS__", strconv.FormatBool(c.config.SeedFromRobots),
		"__SITEMAP__", strconv.FormatBool(c.config.SeedFromSitemap),
	).Replace(seedDiscoverScript)

	raw, ok := evalAwaitCtx(ctx, page, script, seedDiscoverTimeout, "frontier-seed")
	if !ok {
		return nil
	}
	jsonStr, ok := raw.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return nil
	}
	var discovered []string
	if err := parseJSONLinks(jsonStr, &discovered); err != nil || len(discovered) == 0 {
		return nil
	}

	// Early pruning only — fetchURLsInPage (admissibleFetchURLs) is the
	// enforcement point. Filtering here keeps SeedURLsDiscovered and the browse
	// selection to in-scope locations.
	inScope := c.filterInScope(discovered)
	if len(inScope) == 0 {
		return nil
	}

	c.mu.Lock()
	c.stats.SeedURLsDiscovered = len(inScope)
	c.mu.Unlock()
	zap.L().Info("Frontier seeded from robots.txt / sitemap",
		zap.Int("urls", len(inScope)))

	// Record everything (cheap), then browse a bounded, shape-diverse slice.
	c.fetchURLsInPage(ctx, page, inScope, "seed-url")
	return selectCrawlableSeeds(inScope, c.config.SeedMaxCrawlURLs)
}

// crawlSeedURLs navigates to each seed location and folds the resulting page
// into the state graph, so its clickables join the frontier and the ordinary
// crawl loop continues from there. declared are the robots/sitemap locations,
// extra the caller-supplied ones (already deduped against declared); both are
// browsed the same way and counted apart. Failures are skipped rather than
// fatal: a sitemap routinely outlives the pages it lists.
func (c *Crawler) crawlSeedURLs(ctx context.Context, page *browser.Page, declared, extra []string) {
	if len(declared) == 0 && len(extra) == 0 {
		return
	}
	visited, extraVisited := 0, 0
	for i, u := range append(append(make([]string, 0, len(declared)+len(extra)), declared...), extra...) {
		if ctx.Err() != nil || c.shouldTerminate(ctx) {
			break
		}
		previous := c.primary.stateMachine.GetCurrentState()
		if err := page.NavigateCtx(ctx, u); err != nil {
			zap.L().Debug("Seed navigation failed", zap.String("url", u), zap.Error(err))
			continue
		}
		if !c.isInScope(page) {
			continue
		}
		c.checkOnURLState(ctx, c.primary, page, previous, u)
		if i < len(declared) {
			visited++
		} else {
			extraVisited++
		}
	}
	if visited > 0 || extraVisited > 0 {
		c.mu.Lock()
		c.stats.SeedURLsCrawled = visited
		c.stats.ExtraSeedsCrawled = extraVisited
		c.mu.Unlock()
		zap.L().Info("Seed locations browsed into the crawl frontier",
			zap.Int("visited", visited), zap.Int("extra_visited", extraVisited))
	}
}

// selectCrawlableSeeds picks which discovered locations are worth a browser
// visit, capped at limit.
//
// A sitemap is usually dominated by one shape repeated thousands of times
// (/blog/<slug>, /product/<id>) whose pages differ only in content. Visiting
// them in listed order would spend the entire budget inside one template and
// never reach the handful of structurally distinct sections further down the
// file. Selection therefore rounds over path shapes — taking one URL from each
// distinct shape before taking a second from any — so a fixed budget buys the
// widest structural spread the file offers. Non-document extensions are dropped:
// they are already recorded by priming and a browser adds nothing.
func selectCrawlableSeeds(urls []string, limit int) []string {
	if limit <= 0 || len(urls) == 0 {
		return nil
	}

	byShape := make(map[string][]string)
	var shapeOrder []string
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if !seedIsDocument(u.Path) {
			continue
		}
		shape := seedPathShape(u.Path)
		if _, seen := byShape[shape]; !seen {
			shapeOrder = append(shapeOrder, shape)
		}
		byShape[shape] = append(byShape[shape], raw)
	}
	if len(shapeOrder) == 0 {
		return nil
	}
	// Shapes closer to the root first: a section index is a better crawl entry
	// point than a leaf inside it.
	sort.SliceStable(shapeOrder, func(i, j int) bool {
		return strings.Count(shapeOrder[i], "/") < strings.Count(shapeOrder[j], "/")
	})

	out := make([]string, 0, limit)
	for round := 0; len(out) < limit; round++ {
		progressed := false
		for _, shape := range shapeOrder {
			bucket := byShape[shape]
			if round >= len(bucket) {
				continue
			}
			out = append(out, bucket[round])
			progressed = true
			if len(out) >= limit {
				break
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// seedPathShape reduces a path to its structural template by replacing
// identifier-looking segments with a placeholder, so /product/1 and /product/2
// are recognised as the same shape while /product and /admin are not.
func seedPathShape(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i, seg := range segments {
		if seedSegmentIsIdentifier(seg) {
			segments[i] = "*"
		}
	}
	return "/" + strings.Join(segments, "/")
}

// seedSegmentIsIdentifier reports whether a path segment looks like a per-record
// identifier rather than a named section: anything the shared pathshape
// normalizer collapses (a number, uuid, hash, date, …), plus a long slug that
// carries digits (2026-08-06-some-post-title). The slug rule is seed-sampling
// specific — pathshape never collapses slugs — and only widens grouping, which
// costs nothing here beyond seed diversity.
func seedSegmentIsIdentifier(seg string) bool {
	if seg == "" {
		return false
	}
	if pathshape.Kind(seg).Dynamic() {
		return true
	}
	digits := 0
	for _, r := range seg {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits > 0 && len([]rune(seg)) >= 12 // dated slug
}

// seedIsDocument reports whether a path is worth rendering in a browser. A known
// non-document extension (image, stylesheet, archive, feed) is not — priming
// already recorded it and a navigation would only download it again.
func seedIsDocument(path string) bool {
	dot := strings.LastIndexByte(path, '.')
	slash := strings.LastIndexByte(path, '/')
	if dot < 0 || dot < slash {
		return true // extensionless — treat as a route
	}
	switch strings.ToLower(path[dot+1:]) {
	case "html", "htm", "xhtml", "php", "asp", "aspx", "jsp", "do", "action", "cfm":
		return true
	case "":
		return true
	}
	return false
}

// maxPopupSeedRounds bounds popup-seed exploration rounds per crawl.
const maxPopupSeedRounds = 3

// crawlPopupSeeds browses the popup URLs recorded since the last call into the
// state graph and returns how many became reachable states.
func (c *Crawler) crawlPopupSeeds(ctx context.Context, page *browser.Page) int {
	c.mu.Lock()
	pending := append([]string(nil), c.stats.PopupURLs[c.popupSeeded:]...)
	c.popupSeeded = len(c.stats.PopupURLs)
	c.mu.Unlock()
	visited := 0
	for _, u := range pending {
		if ctx.Err() != nil || c.shouldTerminate(ctx) {
			break
		}
		previous := c.primary.stateMachine.GetCurrentState()
		if err := page.NavigateCtx(ctx, u); err != nil {
			zap.L().Debug("Popup seed navigation failed", zap.String("url", u), zap.Error(err))
			continue
		}
		if !c.isInScope(page) {
			continue
		}
		c.checkOnURLState(ctx, c.primary, page, previous, u)
		visited++
	}
	if visited > 0 {
		c.mu.Lock()
		c.stats.PopupSeedsCrawled += visited
		c.mu.Unlock()
		zap.L().Info("Popup URLs browsed into the crawl frontier", zap.Int("visited", visited))
	}
	return visited
}
