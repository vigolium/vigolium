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
// Integration tests for iframe crawling with exact state/edge count assertions.
// =============================================================================

// TestIFrameCrawlable tests crawling iframes.
// Expected: 13 states, 23 edges
//
// Test site has 11 clickable elements:
// - index.html: 3 anchors (#top-click-1, #top-click-2, #top-click-3)
// - iframe.html (frame0): 2 anchors
// - page0-0-0.html (frame0.nested): 1 anchor + 2 inputs (button001, button002)
// - iframe2.html (frame1): 2 anchors
// - subiframe.html (frame1.frame10): 1 anchor
//
// The extra state/edges come from button001's toggle behavior:
// - Click button001: value changes from "Click Me (c4)!" → "Click Me !"
// - With ClickOnce+Attributes, button001 is seen as NEW element in new state
// - Click button001 again: value toggles to "I'm clicked", creating another state
// - CandidateElement.getUniqueString() includes all attributes, making re-clicks generate new states
func TestIFrameCrawlable(t *testing.T) {
	const (
		NUMBER_OF_STATES = 13
		NUMBER_OF_EDGES  = 23
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.CrawlFrames = true
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond
	cfg.ClickSelectors = []string{"a", "input"}
	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestIFrameExclusions tests excluding specific iframes from crawling.
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 5
func TestIFrameExclusions(t *testing.T) {
	const (
		NUMBER_OF_STATES = 4
		NUMBER_OF_EDGES  = 5
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.CrawlFrames = true
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	cfg.ExcludeFrames = []string{"frame1", "sub", "frame0"}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestIFramesNotCrawled tests disabling iframe crawling entirely.
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 5
func TestIFramesNotCrawled(t *testing.T) {
	const (
		NUMBER_OF_STATES = 4
		NUMBER_OF_EDGES  = 5
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.CrawlFrames = false
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestIFramesWildcardsNotCrawled tests wildcard exclusion of iframes.
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 5
func TestIFramesWildcardsNotCrawled(t *testing.T) {
	const (
		NUMBER_OF_STATES = 4
		NUMBER_OF_EDGES  = 5
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.CrawlFrames = true
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	// Using glob pattern - frame% matches frame0, frame1, etc.
	cfg.ExcludeFrames = []string{"frame*", "sub"}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestCrawlingOnlySubFrames tests excluding nested frame paths.
// Expected: NUMBER_OF_STATES = 12, NUMBER_OF_EDGES = 21
func TestCrawlingOnlySubFrames(t *testing.T) {
	const (
		NUMBER_OF_STATES = 12
		NUMBER_OF_EDGES  = 21
	)

	server := testutil.IFrameSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.CrawlFrames = true
	cfg.MaxDuration = 120 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	cfg.ExcludeFrames = []string{"frame1.frame10"}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}

	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}
