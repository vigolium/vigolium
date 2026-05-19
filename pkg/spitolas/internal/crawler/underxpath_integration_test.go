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
// Integration tests for XPath-based click exclusion rules.
// =============================================================================

// TestDontClickUnderXPath tests XPath-based click exclusion rules.
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

	cfg.ClickSelectors = []string{"a"}

	cfg.DontClickSelectors = []string{
		"a.noClickClass", // underXPath with class
		"a#noClickId",    // withAttribute id
	}

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

	if result.StateCount() != EXPECTED_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), EXPECTED_STATES)
	}
}
