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
// Tests clickable element detection via CDP event listener detection.
// =============================================================================

// TestCrawlWithClickableDetection tests clickable element detection via CDP.
// Expected: numStates = 2
//
// Site structure:
// - index.html: Has #clickable div with jQuery click handler that loads clicked.html into #content
// - #ignore div has hover handler (should NOT be clicked)
//
// - clickElementsWithClickEventHandler() → Enable CDP detection (UseCDPDetection = true)
// - clickOnce(true) → Already default in config
// - Chrome HEADLESS with CDP enabled
func TestCrawlWithClickableDetection(t *testing.T) {
	const (
		NUMBER_OF_STATES = 2
	)

	server := testutil.ClickablesSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// builder.crawlRules().clickElementsWithClickEventHandler()
	// builder.crawlRules().clickOnce(true)
	// BrowserConfiguration(CHROME_HEADLESS, 1, options) with USE_CDP=true
	cfg.Headless = true
	cfg.UseCDPDetection = true // clickElementsWithClickEventHandler
	cfg.ClickOnce = true       // clickOnce(true)
	cfg.MaxStates = 0          // Unlimited
	cfg.MaxDepth = 0           // Unlimited
	cfg.MaxDuration = 60 * time.Second

	// CRITICAL: Add specific selector for the clickable div
	// finds elements with JavaScript event handlers. However, Chrome's getEventListeners
	// we explicitly include the #clickable selector which is the div with the click handler.
	// Note: We don't add all "div" elements as that would include #ignore (hover only)
	// and cause extra state changes.
	cfg.ClickSelectors = append(cfg.ClickSelectors, "#clickable")

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

	// where numStates = 2
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d",
			result.StateCount(), NUMBER_OF_STATES)
	}
}
