//go:build integration

package browser

import (
	"testing"
	"time"
)

// TestCDPGetEventListeners tests getting event listeners for an element.
func TestCDPGetEventListeners(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Navigate to page with JavaScript event handlers
	if err := page.Navigate(server.URL + "/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Wait for JavaScript to load
	time.Sleep(1 * time.Second)

	// Get event listeners for an anchor element
	listeners, err := page.GetEventListeners("a")
	if err != nil {
		t.Fatalf("GetEventListeners() failed: %v", err)
	}

	// index.html has click handlers on anchor elements
	if listeners == nil {
		t.Fatal("Expected listeners map, got nil")
	}

	// Verify click event exists in listeners
	clickListeners, hasClick := listeners["click"]
	if !hasClick {
		t.Error("Expected 'click' event listener on anchor element")
	}

	// Verify click listeners is an array with at least 1 handler
	if arr, ok := clickListeners.([]interface{}); ok {
		if len(arr) < 1 {
			t.Errorf("Expected at least 1 click listener, got %d", len(arr))
		}
	}
}

// TestCDPGetAllEventListeners tests getting event listeners for multiple elements.
func TestCDPGetAllEventListeners(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	time.Sleep(1 * time.Second)

	// Get event listeners for anchor elements by xpath
	xpaths := []string{"//a"}
	listeners, err := page.GetAllEventListeners(xpaths)
	if err != nil {
		t.Fatalf("GetAllEventListeners() failed: %v", err)
	}

	// index.html has multiple anchors with click handlers
	if len(listeners) == 0 {
		t.Fatal("Expected at least 1 element with click listeners")
	}

	// Verify first listener has click
	if !listeners[0].HasClick {
		t.Error("Expected first anchor to have click handler")
	}

	if listeners[0].ListenerCount < 1 {
		t.Errorf("Expected ListenerCount >= 1, got %d", listeners[0].ListenerCount)
	}
}

// TestCDPDOMSnapshot tests capturing a DOM snapshot.
// simple.html has 1 document with specific structure
func TestCDPDOMSnapshot(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Capture DOM snapshot
	snapshot, err := page.DOMSnapshot()
	if err != nil {
		t.Fatalf("DOMSnapshot() failed: %v", err)
	}

	// simple.html is a single document with no iframes
	if snapshot.Documents != 1 {
		t.Errorf("Expected exactly 1 document for simple.html, got %d", snapshot.Documents)
	}

	if snapshot.RawResult == nil {
		t.Error("DOMSnapshot RawResult should not be nil")
	}
}

// TestCDPEnableNetwork tests enabling network domain.
func TestCDPEnableNetwork(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Enable network domain
	if err := page.EnableNetwork(); err != nil {
		t.Fatalf("EnableNetwork() failed: %v", err)
	}

	// Navigate after enabling network
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Verify page loaded with exact title
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Title() failed: %v", err)
	}

	if title != "Simple page" {
		t.Errorf("Expected title 'Simple page', got %q", title)
	}
}

// TestCDPSetRequestInterception tests request interception setup.
func TestCDPSetRequestInterception(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Set up request interception for JS and CSS
	patterns := []string{"*.js", "*.css"}
	if err := page.SetRequestInterception(patterns); err != nil {
		t.Fatalf("SetRequestInterception() failed: %v", err)
	}

	// Navigate should still work
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Verify page content loaded correctly
	htmlContent, err := page.HTML()
	if err != nil {
		t.Fatalf("HTML() failed: %v", err)
	}

	if htmlContent == "" {
		t.Error("Page HTML should not be empty after navigation with interception")
	}
}

// TestCDPGetLayoutMetrics tests getting page layout metrics.
func TestCDPGetLayoutMetrics(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Get layout metrics
	metrics, err := page.GetLayoutMetrics()
	if err != nil {
		t.Fatalf("GetLayoutMetrics() failed: %v", err)
	}

	// Viewport should match config defaults (1920x1080)
	expectedWidth := 1920.0
	expectedHeight := 1080.0

	if metrics.ViewportWidth != expectedWidth {
		t.Errorf("Expected ViewportWidth %f, got %f", expectedWidth, metrics.ViewportWidth)
	}

	if metrics.ViewportHeight != expectedHeight {
		t.Errorf("Expected ViewportHeight %f, got %f", expectedHeight, metrics.ViewportHeight)
	}

	// Content dimensions should be positive
	if metrics.ContentWidth <= 0 {
		t.Errorf("ContentWidth should be positive, got %f", metrics.ContentWidth)
	}

	if metrics.ContentHeight <= 0 {
		t.Errorf("ContentHeight should be positive, got %f", metrics.ContentHeight)
	}
}

// TestCDPGetEventListenersOnClickableElement tests event listeners on iframe page elements.
func TestCDPGetEventListenersOnClickableElement(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Navigate to iframe/index.html which has 3 onclick links
	if err := page.Navigate(server.URL + "/iframe/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	time.Sleep(1 * time.Second)

	// This page has onclick handlers on #top-click-1
	listeners, err := page.GetEventListeners("#top-click-1")
	if err != nil {
		t.Fatalf("GetEventListeners() failed: %v", err)
	}

	// Verify click listener exists
	if listeners == nil {
		t.Fatal("Expected listeners map, got nil")
	}

	clickListeners, hasClick := listeners["click"]
	if !hasClick {
		t.Error("Expected 'click' event listener on #top-click-1")
	}

	// Verify exactly 1 click handler
	if arr, ok := clickListeners.([]interface{}); ok {
		if len(arr) != 1 {
			t.Errorf("Expected exactly 1 click listener, got %d", len(arr))
		}
	}
}

// TestCDPDOMSnapshotWithIframes tests DOM snapshot with iframes.
func TestCDPDOMSnapshotWithIframes(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Navigate to page with iframes
	if err := page.Navigate(server.URL + "/iframe/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	time.Sleep(1 * time.Second)

	// Capture DOM snapshot
	snapshot, err := page.DOMSnapshot()
	if err != nil {
		t.Fatalf("DOMSnapshot() failed: %v", err)
	}

	// iframe/index.html structure:
	// - main document (1)
	// - frame0 -> iframe.html (1) -> subiframe.html (1)
	// - frame1 -> iframe2.html (1)
	// Total: 5 documents (based on test run observation)
	expectedDocuments := 5
	if snapshot.Documents != expectedDocuments {
		t.Errorf("Expected %d documents with iframes, got %d", expectedDocuments, snapshot.Documents)
	}
}

// TestCDPGetLayoutMetricsWithScrolling tests layout metrics stability after scroll.
func TestCDPGetLayoutMetricsWithScrolling(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Get initial metrics
	metrics1, err := page.GetLayoutMetrics()
	if err != nil {
		t.Fatalf("GetLayoutMetrics() 1 failed: %v", err)
	}

	// Scroll the page
	_, err = page.Eval("(() => window.scrollTo(0, 100))()")
	if err != nil {
		t.Fatalf("Scroll failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Get metrics after scroll
	metrics2, err := page.GetLayoutMetrics()
	if err != nil {
		t.Fatalf("GetLayoutMetrics() 2 failed: %v", err)
	}

	// Viewport size must remain exactly the same after scroll
	if metrics1.ViewportWidth != metrics2.ViewportWidth {
		t.Errorf("ViewportWidth changed after scroll: %f -> %f", metrics1.ViewportWidth, metrics2.ViewportWidth)
	}

	if metrics1.ViewportHeight != metrics2.ViewportHeight {
		t.Errorf("ViewportHeight changed after scroll: %f -> %f", metrics1.ViewportHeight, metrics2.ViewportHeight)
	}

	// Content size must remain exactly the same after scroll
	if metrics1.ContentWidth != metrics2.ContentWidth {
		t.Errorf("ContentWidth changed after scroll: %f -> %f", metrics1.ContentWidth, metrics2.ContentWidth)
	}

	if metrics1.ContentHeight != metrics2.ContentHeight {
		t.Errorf("ContentHeight changed after scroll: %f -> %f", metrics1.ContentHeight, metrics2.ContentHeight)
	}
}
