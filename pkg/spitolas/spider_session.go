package spitolas

import (
	"context"
	"fmt"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/crawler"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

// SpiderSession owns ONE browser context reused across several crawls — typically
// every re-spider seed for a single host. Sharing the browser means cookies,
// local storage, and any authenticated session established on one seed persist to
// the next, and capture-level dedup spans all of a host's seeds, instead of
// paying a fresh browser launch (and discarding the session) for every seed.
//
// Each Crawl builds a FRESH internal crawler (fresh state graph / state machine /
// candidates), so per-seed crawl state never bleeds between seeds — only the
// browser, capture, and record writer are shared. Close must be called to flush
// the writer and tear the browser down; after a Crawl abandoned by a caller-side
// watchdog the browser may be wedged, so the caller should stop using the session
// and let Close (or process exit) reclaim it.
type SpiderSession struct {
	base    SpiderConfig
	writer  *network.RepositoryWriter
	pool    *browser.Pool
	br      *browser.Browser
	capture *network.Capture
	closed  bool
}

// NewSpiderSession launches one browser, starts browser-level capture bound to a
// shared writer, and returns a session ready to crawl seeds. base supplies the
// browser-level settings (engine/path/proxy/headless), the writer source, and the
// scope filter; base.TargetURL only needs to be a representative same-host URL
// (its host seeds the capture's log filter). Per-seed URLs are passed to Crawl.
func NewSpiderSession(ctx context.Context, base SpiderConfig, repo RecordSaver) (*SpiderSession, error) {
	crawlerCfg, err := buildCrawlerConfig(base)
	if err != nil {
		return nil, err
	}
	// The session is single-browser by design (one context reused across seeds),
	// so never launch more than one regardless of the configured BrowserCount.
	crawlerCfg.BrowserCount = 1

	source := base.Source
	if source == "" {
		source = "spidering"
	}
	writer := network.NewRepositoryWriter(repo, source, base.ProjectUUID)
	writer.ScopeFilter = base.ScopeFilter

	pool, err := browser.NewPool(crawlerCfg)
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("spider session: create browser pool: %w", err)
	}
	pool.SetCrawlContext(ctx)

	br := pool.Get()
	if br == nil {
		_ = pool.Close()
		_ = writer.Close()
		return nil, fmt.Errorf("spider session: browser pool returned nil browser")
	}

	targetHost := ""
	if crawlerCfg.URL != nil {
		targetHost = crawlerCfg.URL.Hostname()
	}
	capture := network.New(writer, crawlerCfg.NoColor, base.Silent, base.Verbose,
		base.IncludeResponseBody, base.IncludeHeaders, targetHost, "spider")
	if err := capture.Start(br.RodBrowser()); err != nil {
		_ = pool.Close()
		_ = writer.Close()
		return nil, fmt.Errorf("spider session: start capture: %w", err)
	}

	return &SpiderSession{
		base:    base,
		writer:  writer,
		pool:    pool,
		br:      br,
		capture: capture,
	}, nil
}

// Crawl runs one seed URL on the session's shared browser and returns its result.
// The browser (and thus cookies + capture dedup) carries over from prior seeds.
func (s *SpiderSession) Crawl(ctx context.Context, seedURL string) (*SpiderResult, error) {
	if s.closed {
		return nil, fmt.Errorf("spider session: closed")
	}

	seedCfg := s.base
	seedCfg.TargetURL = seedURL
	crawlerCfg, err := buildCrawlerConfig(seedCfg)
	if err != nil {
		return nil, err
	}
	crawlerCfg.BrowserCount = 1

	c, err := crawler.New(crawlerCfg)
	if err != nil {
		return nil, err
	}
	c.SetWriter(s.writer)

	// Per-seed record count is the shared writer's delta across this crawl. The
	// async writer may not have flushed this seed's tail yet, so the delta can
	// slightly undercount at the boundary; the session-final flush on Close makes
	// the running total exact, and later seeds pick up any lag.
	before := s.writer.Count()
	result, err := c.RunOnBrowser(ctx, s.br, s.capture)
	if err != nil {
		return nil, err
	}
	saved := s.writer.Count() - before
	if saved < 0 {
		saved = 0
	}
	return spiderResultFromCrawl(result, saved), nil
}

// RecordsSaved reports the total records the session has persisted so far across
// all its seeds. Exact after Close (which flushes the writer).
func (s *SpiderSession) RecordsSaved() int {
	return s.writer.Count()
}

// Close flushes the shared writer (via the capture) and tears the browser down.
// Safe to call more than once.
func (s *SpiderSession) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	// Close the capture first — it flushes/closes the writer — then the browser.
	var err error
	if s.capture != nil {
		err = s.capture.Close()
	}
	if s.pool != nil {
		if cerr := s.pool.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
