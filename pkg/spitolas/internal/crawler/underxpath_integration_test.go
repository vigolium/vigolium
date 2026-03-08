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
// CRAWLJAX PARITY: UnderXPathTest.java
// Integration tests for XPath-based click exclusion rules.
// =============================================================================

// TestDontClickUnderXPath tests XPath-based click exclusion rules.
// Crawljax parity: UnderXPathTest.testDontClickUnderXPath()
// Expected: 2 states
//
// The underxpath.html page has:
// - 1 clickable anchor: "This you can click" -> newState('correct')
// - 4 excluded anchors:
//   - id='noClickId': excluded by withAttribute("id", "noClickId")
//   - class='noClickClass': excluded by underXPath("//A[@class=\"noClickClass\"]")
//   - parent id='noChildrenOfId': excluded by dontClickChildrenOf("div").withId("noChildrenOfId")
//   - parent class='noChildrenOfClass': excluded by dontClickChildrenOf("div").withClass("noChildrenOfClass")
//
// Result: Only the correct anchor is clicked, creating 2 states (index + 1)
func TestDontClickUnderXPath(t *testing.T) {
	const (
		// Crawljax exact values from UnderXPathTest.java
		EXPECTED_STATES = 2
	)

	server := testutil.UnderXPathSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URLFor("underxpath.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 0  // Unlimited
	cfg.MaxStates = 0 // Unlimited
	cfg.MaxDuration = 60 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

	// Crawljax: builder.crawlRules().click("a")
	cfg.ClickSelectors = []string{"a"}

	// Crawljax: builder.crawlRules().dontClick("a").underXPath("//A[@class=\"noClickClass\"]")
	// Crawljax: rules.dontClick("a").withAttribute("id", "noClickId")
	cfg.DontClickSelectors = []string{
		"a.noClickClass", // underXPath with class
		"a#noClickId",    // withAttribute id
	}

	// Crawljax: rules.dontClickChildrenOf("div").withClass("noChildrenOfClass")
	// Crawljax: rules.dontClickChildrenOf("div").withId("noChildrenOfId")
	cfg.DontClickChildrenOfSelectors = []string{
		"div.noChildrenOfClass",
		"div#noChildrenOfId",
	}

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

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasStates(2))
	if result.StateCount() != EXPECTED_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates)",
			result.StateCount(), EXPECTED_STATES)
	}
}
