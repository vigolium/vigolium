//go:build integration

package crawler

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// =============================================================================
// Integration tests for download popup handling.
// The crawler should handle download popups gracefully and continue crawling.
// =============================================================================

// TestDownloadPopupHandling tests that the crawler handles download popups correctly.
// Expected: NUMBER_OF_STATES = 2 (download.html and simple.html)
//
// Test scenario:
// - Start at download/download.html
// - Page has 2 links:
//  1. download.blob - triggers a download (should be handled/ignored)
//  2. ../simple.html - regular HTML page (should be crawled)
//
// - Crawler should reach 2 states without getting stuck on download
func TestDownloadPopupHandling(t *testing.T) {
	const (
		NUMBER_OF_STATES = 2
	)

	// Use SiteServer which serves the entire /site directory
	// The download.html references ../simple.html which needs the parent dir
	server := testutil.SiteServer()
	defer server.Close()

	// Start at download/download.html within the site
	startURL := server.URLFor("download/download.html")
	cfg, err := config.New(startURL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// BaseCrawler uses default config:
	// - clickDefaultElements()
	// - CHROME_HEADLESS
	// - unlimitedRuntime
	// - unlimitedCrawlDepth
	cfg.Headless = true
	cfg.MaxDepth = 0
	cfg.MaxStates = 0 // Unlimited
	cfg.MaxDuration = 60 * time.Second
	cfg.WaitAfterEvent = 200 * time.Millisecond
	cfg.WaitAfterReload = 200 * time.Millisecond

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	// States expected:
	// 1. download/download.html - initial state
	// 2. simple.html - after clicking the HTML link
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Debug output
	t.Logf("Crawl completed: %d states, %d edges", result.StateCount(), result.EdgeCount())
	for _, state := range result.Graph.AllStates() {
		t.Logf("  State: %s, URL: %s", state.Name, state.URL)
	}
}
