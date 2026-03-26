//go:build integration

package crawler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// =============================================================================
// Tests custom URL scope filtering for crawl scope boundaries.
// Validates that the crawler respects URL-based scope constraints.
// =============================================================================

// TestCrawlsPagesOnlyInCustomScope tests custom URL scope filtering.
// Expected: 3 states (only in_scope pages)
//
// Site structure:
// - index.html: Links to out_of_scope.html and in_scope.html
// - in_scope.html: Link to in_scope_inner.html
// - in_scope_inner.html: No further links
// - out_of_scope.html: Link to out_of_scope_inner.html (NOT crawled)
// - out_of_scope_inner.html: NOT crawled
//
// - Custom CrawlScope: url -> url.contains("in_scope") || url.endsWith("crawlscope/index.html")
//
// Expected crawled URLs:
// - baseUrl + "crawlscope" (or "crawlscope/")
// - baseUrl + "crawlscope/in_scope.html"
// - baseUrl + "crawlscope/in_scope_inner.html"
func TestCrawlsPagesOnlyInCustomScope(t *testing.T) {
	const (
		// assertThat(crawledUrls.size(), is(3))
		NUMBER_OF_STATES = 3
	)

	server := testutil.CrawlScopeSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL() + "/crawlscope/")
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// CrawlScope crawlScope = url -> url.contains("in_scope") || url.endsWith("crawlscope/index.html")
	// builder.setCrawlScope(crawlScope)
	cfg.SetCrawlScope(func(url string) bool {
		return strings.Contains(url, "in_scope") ||
			strings.HasSuffix(url, "crawlscope/index.html") ||
			strings.HasSuffix(url, "crawlscope/") ||
			strings.HasSuffix(url, "crawlscope")
	})

	cfg.Headless = true
	cfg.MaxStates = 0 // Unlimited
	cfg.MaxDepth = 0  // Unlimited
	cfg.MaxDuration = 60 * time.Second

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

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d = 3)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// assertThat(crawledUrls, hasItems(
	//     baseUrl + "crawlscope",
	//     baseUrl + "crawlscope/in_scope.html",
	//     baseUrl + "crawlscope/in_scope_inner.html"))
	crawledURLs := make(map[string]bool)
	for _, state := range result.Graph.AllStates() {
		crawledURLs[state.URL] = true
	}

	expectedPatterns := []string{
		"crawlscope",          // index page
		"in_scope.html",       // first in-scope page
		"in_scope_inner.html", // nested in-scope page
	}

	for _, pattern := range expectedPatterns {
		found := false
		for url := range crawledURLs {
			if strings.Contains(url, pattern) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected URL containing %q not found in crawled URLs: %v",
				pattern, crawledURLs)
		}
	}

	// Verify out_of_scope pages are NOT in the crawled URLs
	excludedPatterns := []string{
		"out_of_scope.html",
		"out_of_scope_inner.html",
	}

	for _, pattern := range excludedPatterns {
		for url := range crawledURLs {
			if strings.Contains(url, pattern) {
				t.Errorf("URL containing %q should NOT be in crawled URLs, but found: %s",
					pattern, url)
			}
		}
	}
}
