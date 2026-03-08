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
// CRAWLJAX PARITY: IFrameTest.java
// Integration tests for iframe crawling with exact state/edge count assertions.
// =============================================================================

// TestIFrameCrawlable tests crawling iframes.
// Crawljax parity: IFrameTest.testIFrameCrawlable()
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
// - This matches Crawljax's CandidateElement.getUniqueString() which includes all attributes
func TestIFrameCrawlable(t *testing.T) {
	const (
		// Crawljax exact values from IFrameTest.java
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
	// Crawljax: builder.crawlRules().click("a"); builder.crawlRules().click("input");
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

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasStates(13))
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasEdges(23))
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: hasEdges)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestIFrameExclusions tests excluding specific iframes from crawling.
// Crawljax parity: IFrameTest.testIframeExclusions()
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 5
func TestIFrameExclusions(t *testing.T) {
	const (
		// Crawljax exact values from IFrameTest.java
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

	// Crawljax: builder.crawlRules().dontCrawlFrame("frame1", "sub", "frame0")
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

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasStates(4))
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasEdges(5))
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: hasEdges)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestIFramesNotCrawled tests disabling iframe crawling entirely.
// Crawljax parity: IFrameTest.testIFramesNotCrawled()
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 5
func TestIFramesNotCrawled(t *testing.T) {
	const (
		// Crawljax exact values from IFrameTest.java
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
	cfg.CrawlFrames = false // Crawljax: builder.crawlRules().crawlFrames(false)
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

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasStates(4))
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasEdges(5))
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: hasEdges)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestIFramesWildcardsNotCrawled tests wildcard exclusion of iframes.
// Crawljax parity: IFrameTest.testIFramesWildcardsNotCrawled()
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 5
func TestIFramesWildcardsNotCrawled(t *testing.T) {
	const (
		// Crawljax exact values from IFrameTest.java
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

	// Crawljax: builder.crawlRules().dontCrawlFrame("frame%", "sub")
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

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasStates(4))
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasEdges(5))
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: hasEdges)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestCrawlingOnlySubFrames tests excluding nested frame paths.
// Crawljax parity: IFrameTest.testCrawlingOnlySubFrames()
// Expected: NUMBER_OF_STATES = 12, NUMBER_OF_EDGES = 21
func TestCrawlingOnlySubFrames(t *testing.T) {
	const (
		// Crawljax exact values from IFrameTest.java
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

	// Crawljax: builder.crawlRules().dontCrawlFrame("frame1.frame10")
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

	// Crawljax parity: assertEquals("States", 12, session.getStateFlowGraph().getAllStates().size())
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: assertEquals States)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertEquals("Clickables", 21, session.getStateFlowGraph().getAllEdges().size())
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: assertEquals Clickables)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}
