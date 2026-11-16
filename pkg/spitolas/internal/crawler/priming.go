package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"

	"github.com/vigolium/vigolium/pkg/safety"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// destructivePathRe matches URL paths that commonly end a session or mutate state
// (logout, delete, unsubscribe, close-account). It is the shared pkg/safety
// pattern, the same one the DOM-side POST-form enumeration applies to form
// controls, so no in-page primer fetches such an endpoint with the browser's live
// credentials.
var destructivePathRe = safety.DestructiveNameRe

// filterDestructiveURLs returns urls with any whose path reads as destructive
// (the shared pattern, or extra: spidering.deny_click_extra, nil when unset)
// removed. A URL that fails to parse is kept — it was already
// same-origin-validated by the discovery script that produced it.
func filterDestructiveURLs(urls []string, extra *regexp.Regexp) []string {
	kept := make([]string, 0, len(urls))
	for _, raw := range urls {
		if u, err := url.Parse(raw); err == nil &&
			(destructivePathRe.MatchString(u.Path) || (extra != nil && extra.MatchString(u.Path))) {
			continue
		}
		kept = append(kept, raw)
	}
	return kept
}

// inPageFetchScript fetches a Go-supplied JSON array of same-origin URLs from the
// page (with credentials, following redirects) so the browser's network capture
// records each one. The %s is replaced with the JSON array. Bounded concurrency
// keeps it from flooding the target. Shared by every in-page URL primer
// (iframe sources, GET-form submits, parameterized anchor links). No backticks:
// embedded as a Go raw string.
const inPageFetchScript = `(async () => {
  const targets = %s;
  const opts = { credentials: 'include', redirect: 'follow' };
  let idx = 0, ok = 0;
  const worker = async () => {
    while (idx < targets.length) {
      const u = targets[idx++];
      try {
        const r = await fetch(u, opts);
        try { await r.arrayBuffer(); } catch (e) {}  // drain so the load finishes
        ok++;
      } catch (e) {}
    }
  };
  await Promise.all(Array.from({length: Math.min(6, targets.length)}, worker));
  return ok;
})()`

// primeChunkSize bounds how many URLs go into one in-page fetch eval.
//
// The eval is bounded by iframePrimeTimeout and runs 6 requests concurrently, so
// a list far larger than the window can drain does not merely finish late — it
// hits the bound, returns an error, and the whole batch is reported as failed
// even though the page is still fetching. Sized so a chunk completes inside the
// window at an unremarkable per-request latency, and so a slow host costs one
// chunk rather than the entire list.
const primeChunkSize = 120

// fetchURLsInPage fetches urls in-page with bounded concurrency so the browser's
// network capture records them, in chunks that each fit the eval's time bound.
// The fetch eval runs on a goroutine so crawl-context cancellation returns
// promptly even if CDP is slow. Best-effort: an empty list is a no-op and any
// failure is logged at debug (tagged with kind) and swallowed. This is the shared
// tail of every in-page URL primer (iframe/form/anchor/seed/speculative).
// Returns how many URLs were actually fetched (chunks that completed).
func (c *Crawler) fetchURLsInPage(ctx context.Context, page *browser.Page, urls []string, kind string) int {
	if page == nil || len(urls) == 0 || ctx.Err() != nil {
		return 0
	}
	urls, denied := c.admissibleFetchURLs(urls)
	if denied > 0 {
		zap.L().Debug("In-page URLs outside the operator scope not fetched",
			zap.String("kind", kind), zap.Int("denied", denied))
	}
	if len(urls) == 0 {
		return 0
	}

	fetched := 0
	for start := 0; start < len(urls); start += primeChunkSize {
		if ctx.Err() != nil {
			break
		}
		end := min(start+primeChunkSize, len(urls))
		chunk := urls[start:end]

		payload, err := json.Marshal(chunk)
		if err != nil {
			continue
		}
		script := fmt.Sprintf(inPageFetchScript, string(payload))

		if _, ok := evalAwaitCtx(ctx, page, script, iframePrimeTimeout, "prime:"+kind); !ok {
			// A chunk that timed out says the host is slower than the window; the
			// remaining chunks would fare no better, so stop rather than spend the
			// budget discovering that repeatedly.
			break
		}
		fetched += len(chunk)
	}

	zap.L().Debug("In-page URLs primed",
		zap.String("kind", kind),
		zap.Int("requested", len(urls)),
		zap.Int("fetched", fetched))
	return fetched
}

// admissibleFetchURLs is the enforcement point for every in-page URL primer
// (iframe, GET-form, anchor, seed, speculative): it returns the urls a primer
// may deliberately request and how many were denied by scope. Applied here —
// the shared tail — so no primer decides for itself:
//   - destructive-looking paths are dropped (live credentials ride along);
//   - so is anything outside the operator's crawl scope, and any host the crawl
//     denied as a login wall. The scripts' own same-origin checks are a weaker
//     boundary than a path-scoped operator scope.
//
// Scope denials are counted in Stats.AuxFetchesDenied. Without a custom scope
// (CrawlScope nil) only wall hosts are refused, as before.
func (c *Crawler) admissibleFetchURLs(urls []string) ([]string, int) {
	urls = filterDestructiveURLs(urls, c.extractor.DenyClickExtra())
	kept := make([]string, 0, len(urls))
	denied := 0
	for _, raw := range urls {
		if c.auxFetchDenied(raw) {
			denied++
			continue
		}
		kept = append(kept, raw)
	}
	if denied > 0 {
		c.mu.Lock()
		c.stats.AuxFetchesDenied += denied
		c.mu.Unlock()
	}
	return kept, denied
}

// auxFetchDenied reports whether an auxiliary fetch of raw is outside the
// operator's boundary. A URL that fails to parse is denied only under a
// custom scope, which cannot vouch for it.
func (c *Crawler) auxFetchDenied(raw string) bool {
	u, err := url.Parse(raw)
	if err == nil && c.isWallHost(u.Hostname()) {
		return true
	}
	if c.config.CrawlScope == nil {
		return false
	}
	return err != nil || !c.config.CrawlScope(raw)
}
