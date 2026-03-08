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
// CRAWLJAX PARITY: CrawlHiddenElementsTest.java
// Tests handling of hidden HTML elements (CSS display: none).
// References GitHub Issue #97 which deals with partial workaround for hidden element crawling.
// =============================================================================

// TestHiddenElementsSiteCrawl tests crawling with hidden anchors enabled.
// Crawljax parity: CrawlHiddenElementsTest.testHiddenElementsSiteCrawl()
// Expected: withIssue97 = 3 - 1 = 2 states
//
// Site structure:
// - index.html: Has hover div that shows/hides links div
// - Links: a.html (href anchor), b.html (JavaScript click anchor)
// - Hidden links initially with display: none
//
// Configuration (matching Crawljax):
// - crawlHiddenAnchors(true) → Enable crawling of hidden anchor elements
//
// Note: This is a partial hack using HREF link following (see Issue #97 comment).
func TestHiddenElementsSiteCrawl(t *testing.T) {
	const (
		// Crawljax exact value from CrawlHiddenElementsTest.java line 36
		// int withIssue97 = 3 - 1;
		NUMBER_OF_STATES = 2
	)

	server := testutil.HiddenElementsSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Crawljax configuration parity:
	// builder.crawlRules().crawlHiddenAnchors(true)
	cfg.Headless = true
	cfg.CrawlHiddenAnchors = true // crawlHiddenAnchors(true)
	cfg.MaxStates = 0             // Unlimited
	cfg.MaxDepth = 0              // Unlimited
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

	// Crawljax parity: assertThat(stateFlowGraph, hasStates(withIssue97))
	// where withIssue97 = 3 - 1 = 2
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: withIssue97 = 3 - 1 = 2)",
			result.StateCount(), NUMBER_OF_STATES)
	}
}

// TestHiddenElementsNotCrawled tests that hidden elements are skipped by default.
// Crawljax parity: CrawlHiddenElementsTest.whenHiddenElementsOfItShouldNotCrawl()
// Expected: expectedStates = 3 - 2 = 1 state
//
// Configuration (matching Crawljax):
// - Default config (crawlHiddenAnchors = false, the default)
//
// Note: This test demonstrates the default behavior where hidden elements are not crawled.
// The bug #97 causes 2 states to be missed, resulting in only 1 state being discovered.
func TestHiddenElementsNotCrawled(t *testing.T) {
	const (
		// Crawljax exact value from CrawlHiddenElementsTest.java line 49
		// int expectedStates = 3 - 2;
		NUMBER_OF_STATES = 1
	)

	server := testutil.HiddenElementsSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Crawljax configuration parity:
	// Default configuration (no custom rules)
	// CrawlHiddenAnchors is false by default (matching Java Crawljax)
	cfg.Headless = true
	cfg.CrawlHiddenAnchors = false // Default - hidden anchors NOT crawled
	cfg.MaxStates = 0              // Unlimited
	cfg.MaxDepth = 0               // Unlimited
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

	// Crawljax parity: assertThat(stateFlowGraph, hasStates(expectedStates))
	// where expectedStates = 3 - 2 = 1
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: expectedStates = 3 - 2 = 1)",
			result.StateCount(), NUMBER_OF_STATES)
	}
}
