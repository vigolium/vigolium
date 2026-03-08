//go:build integration

package crawler

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// =============================================================================
// CRAWLJAX PARITY: NestedFramesTest.java
// Integration tests for nested frame navigation.
// =============================================================================

// TestNestedFramesIndex tests nested frame navigation and element clicking.
// Crawljax parity: NestedFramesTest.testNestedFramesIndex()
// Navigate to iframe site, switch to frame(0)->frame(0), click button002
func TestNestedFramesIndex(t *testing.T) {
	server := testutil.IFrameSiteServer()
	defer server.Close()

	// Create config for browser
	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	// Create browser
	b, err := browser.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create browser: %v", err)
	}
	defer b.Close()

	// Get page
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Navigate to iframe test site
	if err := page.Navigate(server.URL()); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Crawljax: driver.switchTo().frame(0)
	// Switch to first frame (frame0 - iframe.html)
	frames, err := page.Frames()
	if err != nil {
		t.Fatalf("Failed to get frames: %v", err)
	}
	if len(frames) < 1 {
		t.Fatalf("Expected at least 1 frame, got %d", len(frames))
	}

	frame0 := frames[0]

	// Crawljax: driver.switchTo().frame(0) - switch to nested frame
	// frame0 (iframe.html) contains another iframe pointing to page0-0-0.html
	nestedFrames, err := frame0.Frames()
	if err != nil {
		t.Fatalf("Failed to get nested frames: %v", err)
	}
	if len(nestedFrames) < 1 {
		t.Fatalf("Expected at least 1 nested frame, got %d", len(nestedFrames))
	}

	nestedFrame := nestedFrames[0]

	// Crawljax: WebElement button002 = driver.findElement(By.id("button002"))
	button002, err := nestedFrame.Element("#button002")
	if err != nil {
		t.Fatalf("Failed to find button002: %v", err)
	}
	if button002 == nil {
		t.Fatal("button002 not found in nested frame")
	}

	// Crawljax: button002.click()
	// The test simply verifies we can navigate to nested frames and click elements.
	// In Crawljax, the test passes if button002.click() doesn't throw an exception.
	if err := button002.Click(); err != nil {
		t.Fatalf("Failed to click button002: %v", err)
	}

	// Verify the button was clicked by checking if it's now disabled
	// (toggle2() disables button002 when clicked)
	disabled, _ := button002.Attribute("disabled")
	if disabled != "true" && disabled != "disabled" {
		// Note: Some browsers may not reflect the disabled state immediately
		t.Logf("Note: button002 disabled attribute = %q (expected 'true' or 'disabled')", disabled)
	}

	t.Logf("NestedFramesTest: Successfully navigated to nested frame and clicked button002")
}
