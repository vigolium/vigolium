package crawler

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// anchorLinkDiscoverScript enumerates same-origin <a href> links in the live,
// post-render DOM that carry a query string, and returns them (absolute,
// deduped) as a JSON array. It targets parameterized links a framework renders
// client-side — e.g. ginandjuice's React category filter mounts
// <a href="/catalog?category=Books"> into #react-container — which the served
// HTML never contained. Path-only links are left to the ordinary interaction
// crawl; only query-bearing links (category/filter/pagination/detail) are
// primed here. No backticks: embedded as a Go raw string.
const anchorLinkDiscoverScript = `(() => {
  const out = [];
  const seen = new Set();
  const DESTRUCTIVE = /log\s*out|sign\s*out|logout|signout|delete|destroy|(?:^|[^a-z])remove|deactivate|unsubscribe|close[-_]?account|cancel[-_]?account/i;
  let anchors;
  try { anchors = document.querySelectorAll('a[href]'); } catch (e) { anchors = []; }
  for (const a of anchors) {
    const raw = a.getAttribute('href');
    if (!raw) continue;
    if (raw.startsWith('#') || raw.startsWith('javascript:') ||
        raw.startsWith('mailto:') || raw.startsWith('tel:')) continue;
    let u;
    try { u = new URL(raw, location.href); } catch (e) { continue; }
    if (u.origin !== location.origin) continue;
    // Never prime a destructive endpoint with the browser's live credentials: a GET
    // to /logout, /account/delete, /unsubscribe can mutate state or end the session.
    if (DESTRUCTIVE.test(u.pathname)) continue;
    if (!u.search || u.search === '?') continue;   // only parameterized links
    const href = u.href;
    if (seen.has(href)) continue;
    seen.add(href);
    out.push(href);
  }
  return JSON.stringify(out);
})()`

// primeAnchorLinks harvests the same-origin, query-bearing <a href> links in the
// live DOM and fetches the new ones in-page so the browser's network capture
// records them. This makes client-rendered parameterized links discoverable
// deterministically, rather than depending on the bounded interaction budget
// happening to click each one. Best-effort: any failure (eval error, timeout,
// context cancellation) is logged at debug and the crawl continues. Deduped and
// per-shape capped across the whole crawl so an id-indexed link set cannot flood
// the target.
func (c *Crawler) primeAnchorLinks(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || !c.config.AnchorLinkPriming {
		return
	}
	if ctx.Err() != nil {
		return
	}

	raw, err := page.Eval(anchorLinkDiscoverScript)
	if err != nil {
		zap.L().Debug("Anchor-link discovery failed", zap.Error(err))
		return
	}
	jsonStr, ok := raw.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return
	}
	var discovered []string
	if err := parseJSONLinks(jsonStr, &discovered); err != nil || len(discovered) == 0 {
		return
	}

	toFetch := c.selectUnprimedLinks(discovered, c.config.AnchorLinkMaxAssets, c.config.MaxParamValueVariants)
	c.fetchURLsInPage(ctx, page, toFetch, "anchor-link")
}

// selectUnprimedLinks returns the URLs from in that have not been primed yet this
// crawl, marking them primed. It enforces two caps: a per-shape cap (at most
// perShape distinct value-variants of one path+param-name set — mirrors the
// capture's variant cap so priming never fetches more than the capture keeps) and
// a crawl-wide total cap (maxTotal, <=0 disables). Safe for concurrent use.
func (c *Crawler) selectUnprimedLinks(in []string, maxTotal, perShape int) []string {
	c.primedLinksMu.Lock()
	defer c.primedLinksMu.Unlock()
	if c.primedLinks == nil {
		c.primedLinks = make(map[string]bool)
	}
	if c.primedLinkShapes == nil {
		c.primedLinkShapes = make(map[string]int)
	}
	if perShape < 1 {
		perShape = 1
	}
	out := make([]string, 0, len(in))
	for _, u := range in {
		if maxTotal > 0 && len(c.primedLinks) >= maxTotal {
			break
		}
		if c.primedLinks[u] {
			continue
		}
		shape := linkShapeKey(u)
		if c.primedLinkShapes[shape] >= perShape {
			// Enough distinct value-variants of this shape already primed; skip so
			// an id sweep (?productId=1..N) does not fetch every value.
			continue
		}
		c.primedLinks[u] = true
		c.primedLinkShapes[shape]++
		out = append(out, u)
	}
	return out
}

// linkShapeKey collapses a URL to its value-blind endpoint shape: path plus the
// sorted set of query-parameter NAMES. Two links that differ only in a parameter
// value share a shape, so the per-shape cap in selectUnprimedLinks bounds how many
// value-variants of one endpoint are primed. Mirrors the capture's shape hash.
func linkShapeKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	names := make([]string, 0)
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	return u.Path + "?" + strings.Join(names, ",")
}
