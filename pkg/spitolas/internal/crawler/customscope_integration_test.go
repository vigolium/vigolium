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
// CRAWLJAX PARITY: CrawlWithCustomScopeTest.java
// Tests custom URL scope filtering for crawl scope boundaries.
// Validates that the crawler respects URL-based scope constraints.
// =============================================================================

// TestCrawlsPagesOnlyInCustomScope tests custom URL scope filtering.
// Crawljax parity: CrawlWithCustomScopeTest.crawlsPagesOnlyInCustomScope()
// Expected: 3 states (only in_scope pages)
//
// Site structure:
// - index.html: Links to out_of_scope.html and in_scope.html
// - in_scope.html: Link to in_scope_inner.html
// - in_scope_inner.html: No further links
// - out_of_scope.html: Link to out_of_scope_inner.html (NOT crawled)
// - out_of_scope_inner.html: NOT crawled
//
// Configuration (matching Crawljax):
// - Custom CrawlScope: url -> url.contains("in_scope") || url.endsWith("crawlscope/index.html")
//
// Expected crawled URLs:
// - baseUrl + "crawlscope" (or "crawlscope/")
// - baseUrl + "crawlscope/in_scope.html"
// - baseUrl + "crawlscope/in_scope_inner.html"
func TestCrawlsPagesOnlyInCustomScope(t *testing.T) {
	const (
		// Crawljax exact value from CrawlWithCustomScopeTest.java line 48
		// assertThat(crawledUrls.size(), is(3))
		NUMBER_OF_STATES = 3
	)

	server := testutil.CrawlScopeSiteServer()
	defer server.Close()

	// Use crawlscope/ path as base URL (matching Crawljax's BaseCrawler("crawlscope"))
	cfg, err := config.New(server.URL() + "/crawlscope/")
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Crawljax configuration parity:
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

	// Crawljax parity: assertThat(crawledUrls.size(), is(3))
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: crawledUrls.size() = 3)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: Verify crawled URLs contain expected pages
	// assertThat(crawledUrls, hasItems(
	//     baseUrl + "crawlscope",
	//     baseUrl + "crawlscope/in_scope.html",
	//     baseUrl + "crawlscope/in_scope_inner.html"))
	crawledURLs := make(map[string]bool)
	for _, state := range result.Graph.AllStates() {
		crawledURLs[state.URL] = true
	}

	// Expected URL patterns (based on Crawljax test)
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
