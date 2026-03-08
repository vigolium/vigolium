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
// CRAWLJAX PARITY: SimpleSiteCrawlTest.java, SimpleInputSiteCrawlTest.java,
// SimpleJsSiteCrawlTest.java
// Integration tests using real browser with exact state/edge count assertions.
// =============================================================================

// TestSimpleSiteCrawl tests crawling the simple-site test fixture.
// Crawljax parity: SimpleSiteCrawlTest.testInputCrawlerFlowGraph()
// Expected: NUMBER_OF_STATES = 4, NUMBER_OF_EDGES = 7
//
// Site structure:
// - index.html → a.html (index → a)
// - index.html → b.html (index → b)
// - b.html → c.html (b → c)
// - c.html → b.html (c → b)
// - c.html → index.html (c → index)
//
// States: index, a, b, c = 4
// Edges: index→a, index→b, b→c, c→b, c→index, plus 2 more from traversal = 7
func TestSimpleSiteCrawl(t *testing.T) {
	const (
		// Crawljax exact values from SimpleSiteCrawlTest.java
		NUMBER_OF_STATES = 4
		NUMBER_OF_EDGES  = 7
	)

	server := testutil.SimpleSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
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

	// Crawljax parity: assertThat(stateFlowGraph, hasStates(4))
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: NUMBER_OF_STATES)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertThat(stateFlowGraph, hasEdges(7))
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: NUMBER_OF_EDGES)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestSimpleInputSiteCrawl tests crawling the simple-input-site test fixture.
// Crawljax parity: SimpleInputSiteCrawlTest.testInputCrawlerFlowGraph()
// Expected: NUMBER_OF_STATES = 2, NUMBER_OF_EDGES = 2
//
// Site structure:
// - index.html with form input and button
// - otherState.html after form submission with "Good input"
//
// Note: This test requires form filling with specific values.
// The crawler must fill input with "Good input" and click button to reach otherState.
func TestSimpleInputSiteCrawl(t *testing.T) {
	const (
		// Crawljax exact values from SimpleInputSiteCrawlTest.java
		NUMBER_OF_STATES = 2
		NUMBER_OF_EDGES  = 2
	)

	server := testutil.SimpleInputSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 0
	cfg.MaxDepth = 0
	cfg.FormFillEnabled = true
	cfg.MaxDuration = 60 * time.Second

	// Configure form input to use "Good input" - this is required to trigger state change
	// CRAWLJAX PARITY: Uses Identification(How.id, "input") like Java SimpleInputSiteCrawl
	cfg.AddFormInput("id", "input", "text", "Good input")

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

	// Crawljax parity: assertThat(stateFlowGraph, hasStates(2))
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: NUMBER_OF_STATES)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertThat(stateFlowGraph, hasEdges(2))
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: NUMBER_OF_EDGES)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}

// TestSimpleJsSiteCrawl tests crawling the simple-js-site test fixture.
// Crawljax parity: SimpleJsSiteCrawlTest.testInputCrawlerFlowGraph()
// Expected: NUMBER_OF_STATES = 11, NUMBER_OF_EDGES = 13
//
// Site structure: JavaScript-driven dynamic state changes via AJAX
// - index.html with S1, S2 clickable links
// - payload_2.html through payload_11.html loaded via jQuery AJAX
func TestSimpleJsSiteCrawl(t *testing.T) {
	const (
		// Crawljax exact values from SimpleJsSiteCrawlTest.java
		NUMBER_OF_STATES = 11
		NUMBER_OF_EDGES  = 13
	)

	server := testutil.SimpleJsSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 0
	cfg.MaxDepth = 0
	cfg.MaxDuration = 120 * time.Second

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

	// Crawljax parity: assertThat(stateFlowGraph, hasStates(11))
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: NUMBER_OF_STATES)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertThat(stateFlowGraph, hasEdges(13))
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: NUMBER_OF_EDGES)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}
