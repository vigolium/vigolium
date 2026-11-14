package spitolas

import (
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// BrowserNeedsDownload reports whether a crawl configured with engine and
// browserPath (SpiderConfig.BrowserEngine / BrowserPath) would have to download
// Chrome for Testing before its first page: no configured path, no embedded
// engine binary, no working system browser and no cached CfT copy. It makes no
// network request; it does run `<browser> --version` on each system candidate
// until one answers.
//
// The scan runner asks this before the spidering phase starts its clock, and
// when it is true downloads the browser up front with progress, so a fresh
// machine's ~150 MB download is not charged to the crawl's time budget.
func BrowserNeedsDownload(engine, browserPath string) bool {
	if engine == "" {
		engine = "chromium"
	}
	return browser.NeedsDownload(&config.Config{BrowserEngine: engine, BrowserPath: browserPath})
}

// ErrBrowserLaunch is wrapped by every error that means no browser could be
// started (no binary, or every candidate failed to launch). A caller that sees
// it should stop crawling — every further target would fail the same way —
// and report the phase as failed, not as a crawl that found nothing.
var ErrBrowserLaunch = browser.ErrLaunch
