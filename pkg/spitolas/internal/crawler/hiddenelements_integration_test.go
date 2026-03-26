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
// Tests handling of hidden HTML elements (CSS display: none).
// References GitHub Issue #97 which deals with partial workaround for hidden element crawling.
// =============================================================================

// TestHiddenElementsSiteCrawl tests crawling with hidden anchors enabled.
// Expected: withIssue97 = 3 - 1 = 2 states
//
// Site structure:
// - index.html: Has hover div that shows/hides links div
// - Links: a.html (href anchor), b.html (JavaScript click anchor)
// - Hidden links initially with display: none
//
// - crawlHiddenAnchors(true) → Enable crawling of hidden anchor elements
//
// Note: This is a partial hack using HREF link following (see Issue #97 comment).
func TestHiddenElementsSiteCrawl(t *testing.T) {
	const (
		// int withIssue97 = 3 - 1;
		NUMBER_OF_STATES = 2
	)

	server := testutil.HiddenElementsSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

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

	// where withIssue97 = 3 - 1 = 2
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}
}

// TestHiddenElementsNotCrawled tests that hidden elements are skipped by default.
// Expected: expectedStates = 3 - 2 = 1 state
//
// - Default config (crawlHiddenAnchors = false, the default)
//
// Note: This test demonstrates the default behavior where hidden elements are not crawled.
// The bug #97 causes 2 states to be missed, resulting in only 1 state being discovered.
func TestHiddenElementsNotCrawled(t *testing.T) {
	const (
		// int expectedStates = 3 - 2;
		NUMBER_OF_STATES = 1
	)

	server := testutil.HiddenElementsSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Default configuration (no custom rules)
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

	// where expectedStates = 3 - 2 = 1
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}
}
