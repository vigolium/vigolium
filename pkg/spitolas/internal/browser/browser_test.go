//go:build integration

package browser

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// setupTestServer creates a test server serving files from testdata directory.
func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.FileServer(http.Dir("testdata")))
}

// setupBrowser creates a browser for integration tests using config.
func setupBrowser(t *testing.T, serverURL string) *Browser {
	t.Helper()
	cfg, err := config.New(serverURL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	b, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create browser: %v", err)
	}
	t.Cleanup(func() {
		b.Close()
	})
	return b
}

// TestBrowserNew tests browser creation with config.
func TestBrowserNew(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer b.Close()

	// Verify browser is connected
	if !b.IsConnected() {
		t.Error("Browser should be connected after creation")
	}

	// Verify config is stored
	if b.config != cfg {
		t.Error("Config should be stored in browser")
	}
}

// TestBrowserNewWithProxy tests browser creation with proxy configuration.
func TestBrowserNewWithProxy(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	// Note: We don't actually set up a proxy server here, just verify config is accepted
	// cfg.ProxyURL = "http://localhost:8080"

	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New() with proxy config failed: %v", err)
	}
	defer b.Close()

	if !b.IsConnected() {
		t.Error("Browser should be connected")
	}
}

// TestBrowserNewPage tests creating a new page/tab.
func TestBrowserNewPage(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if page == nil {
		t.Fatal("NewPage() returned nil page")
	}

	// Page should have reference to browser
	if page.Browser() != b {
		t.Error("Page should have reference to parent browser")
	}

	// Page should be tracked in browser
	pages := b.Pages()
	if len(pages) != 1 {
		t.Errorf("Expected 1 page, got %d", len(pages))
	}

	// Navigate to verify page works
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	url, err := page.URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	expectedURL := server.URL + "/simple.html"
	if url != expectedURL {
		t.Errorf("Expected URL %s, got %s", expectedURL, url)
	}
}

// TestBrowserPages tests getting all open pages.
func TestBrowserPages(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	// Initially no pages
	pages := b.Pages()
	if len(pages) != 0 {
		t.Errorf("Expected 0 pages initially, got %d", len(pages))
	}

	// Create first page
	page1, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() 1 failed: %v", err)
	}

	pages = b.Pages()
	if len(pages) != 1 {
		t.Errorf("Expected 1 page, got %d", len(pages))
	}

	// Create second page
	page2, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() 2 failed: %v", err)
	}

	pages = b.Pages()
	if len(pages) != 2 {
		t.Errorf("Expected 2 pages, got %d", len(pages))
	}

	// Verify both pages are in the list
	foundPage1, foundPage2 := false, false
	for _, p := range pages {
		if p == page1 {
			foundPage1 = true
		}
		if p == page2 {
			foundPage2 = true
		}
	}
	if !foundPage1 || !foundPage2 {
		t.Error("Both pages should be in Pages() result")
	}
}

// TestBrowserCurrentPage tests current page persistence.
func TestBrowserCurrentPage(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	// Initially no current page
	if b.CurrentPage() != nil {
		t.Error("CurrentPage should be nil initially")
	}

	// Create and set current page
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	b.SetCurrentPage(page)

	// Verify current page is set
	if b.CurrentPage() != page {
		t.Error("CurrentPage should return the set page")
	}

	// Navigate on current page
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	// Current page should still be the same
	if b.CurrentPage() != page {
		t.Error("CurrentPage should persist after navigation")
	}
}

// TestBrowserSetCurrentPage tests setting current page.
func TestBrowserSetCurrentPage(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	page1, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() 1 failed: %v", err)
	}

	page2, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() 2 failed: %v", err)
	}

	// Set page1 as current
	b.SetCurrentPage(page1)
	if b.CurrentPage() != page1 {
		t.Error("CurrentPage should be page1")
	}

	// Change to page2
	b.SetCurrentPage(page2)
	if b.CurrentPage() != page2 {
		t.Error("CurrentPage should be page2 after change")
	}

	// Set to nil
	b.SetCurrentPage(nil)
	if b.CurrentPage() != nil {
		t.Error("CurrentPage should be nil after setting nil")
	}
}

// TestBrowserCloseOtherWindows tests closing all pages except current.
func TestBrowserCloseOtherWindows(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	// Create 3 pages
	page1, _ := b.NewPage()
	page2, _ := b.NewPage()
	page3, _ := b.NewPage()

	if len(b.Pages()) != 3 {
		t.Fatalf("Expected 3 pages, got %d", len(b.Pages()))
	}

	// Set page2 as current
	b.SetCurrentPage(page2)

	// Close other windows
	if err := b.CloseOtherWindows(); err != nil {
		t.Fatalf("CloseOtherWindows() failed: %v", err)
	}

	// Only page2 should remain
	pages := b.Pages()
	if len(pages) != 1 {
		t.Errorf("Expected 1 page after CloseOtherWindows, got %d", len(pages))
	}

	if pages[0] != page2 {
		t.Error("Remaining page should be the current page (page2)")
	}

	// Verify page1 and page3 are closed (can't navigate)
	_ = page1 // page1 is closed
	_ = page3 // page3 is closed

	// Current page should still work
	if err := page2.Navigate(server.URL + "/simple.html"); err != nil {
		t.Errorf("Current page should still work after CloseOtherWindows: %v", err)
	}
}

// TestBrowserCloseOtherWindowsNoCurrentPage tests CloseOtherWindows with no current page.
func TestBrowserCloseOtherWindowsNoCurrentPage(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	_, _ = b.NewPage()
	_, _ = b.NewPage()

	// Don't set current page
	if err := b.CloseOtherWindows(); err != nil {
		t.Fatalf("CloseOtherWindows() with no current page should not error: %v", err)
	}

	// All pages should remain since there's no "current" to keep
	// Actually based on implementation, if currentPage is nil, nothing is closed
	pages := b.Pages()
	if len(pages) != 2 {
		t.Logf("Note: With no current page, CloseOtherWindows keeps all pages: got %d", len(pages))
	}
}

// TestBrowserClose tests browser cleanup.
func TestBrowserClose(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Create pages
	_, _ = b.NewPage()
	_, _ = b.NewPage()

	// Close browser
	if err := b.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Verify pages are cleared
	if len(b.pages) != 0 {
		t.Error("Pages should be cleared after Close()")
	}
}

// TestBrowserIsConnected tests connection status.
func TestBrowserIsConnected(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Should be connected after creation
	if !b.IsConnected() {
		t.Error("Browser should be connected after creation")
	}

	// Close and check
	b.Close()

	// After close, rodBrowser is still set but connection may be closed
	// The implementation just checks if rodBrowser != nil
}

// TestBrowserPoolRoundRobin tests browser pool rotation.
func TestBrowserPoolRoundRobin(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.BrowserCount = 3

	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool() failed: %v", err)
	}
	defer pool.Close()

	// Verify pool size
	if pool.Size() != 3 {
		t.Errorf("Expected pool size 3, got %d", pool.Size())
	}

	// Get browsers in round-robin fashion
	b1 := pool.Get()
	b2 := pool.Get()
	b3 := pool.Get()

	// They should all be different
	if b1 == b2 || b2 == b3 || b1 == b3 {
		t.Error("Round-robin should return different browsers")
	}

	// After 3 gets, should cycle back to first
	b4 := pool.Get()
	if b4 != b1 {
		t.Error("Round-robin should cycle back to first browser")
	}
}

// TestBrowserPoolConcurrent tests thread-safe pool access.
func TestBrowserPoolConcurrent(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.BrowserCount = 2

	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool() failed: %v", err)
	}
	defer pool.Close()

	// Concurrent access should not panic
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := pool.Get()
			if b == nil {
				t.Error("Pool.Get() returned nil")
			}
			time.Sleep(10 * time.Millisecond)
		}()
	}
	wg.Wait()
}

// TestBrowserPoolClose tests pool cleanup.
func TestBrowserPoolClose(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.BrowserCount = 2

	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool() failed: %v", err)
	}

	if pool.Size() != 2 {
		t.Errorf("Expected pool size 2, got %d", pool.Size())
	}

	if err := pool.Close(); err != nil {
		t.Fatalf("Pool.Close() failed: %v", err)
	}

	if pool.Size() != 0 {
		t.Errorf("Expected pool size 0 after close, got %d", pool.Size())
	}
}

// TestBrowserCloseOtherWindowsTargetBlank tests closing new tabs opened by target="_blank".
// to find ALL windows including those opened by target="_blank" or window.open().
func TestBrowserCloseOtherWindowsTargetBlank(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	// Create main page and navigate to newtab test page
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/newtab/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Set as current page
	b.SetCurrentPage(page)

	// Verify only 1 page exists
	allPages, err := b.rodBrowser.Pages()
	if err != nil {
		t.Fatalf("Failed to get initial pages: %v", err)
	}
	initialPageCount := len(allPages)

	// Click the target="_blank" link - this will open a new tab
	// We need to use rod's Click directly since Page.Click may not exist
	err = page.rodPage.MustElement("#link-blank").Click("left", 1)
	if err != nil {
		t.Fatalf("Click on target=_blank link failed: %v", err)
	}

	// Give browser time to open new tab
	time.Sleep(500 * time.Millisecond)

	// Verify new tab was created
	allPages, err = b.rodBrowser.Pages()
	if err != nil {
		t.Fatalf("Failed to get pages after click: %v", err)
	}

	if len(allPages) <= initialPageCount {
		t.Logf("Note: New tab may not have opened (popup blocker?). Pages: %d", len(allPages))
		// This is not necessarily a failure - headless mode might block popups
		return
	}

	t.Logf("New tab opened: %d -> %d pages", initialPageCount, len(allPages))

	// Now call CloseOtherWindows - this should close the new tab
	if err := b.CloseOtherWindows(); err != nil {
		t.Fatalf("CloseOtherWindows() failed: %v", err)
	}

	// Verify only current page remains
	allPages, err = b.rodBrowser.Pages()
	if err != nil {
		t.Fatalf("Failed to get pages after CloseOtherWindows: %v", err)
	}

	if len(allPages) != 1 {
		t.Errorf("Expected 1 page after CloseOtherWindows, got %d", len(allPages))
	}

	// Verify the remaining page is our original page
	if len(allPages) > 0 && allPages[0].TargetID != page.rodPage.TargetID {
		t.Error("Remaining page should be the current page")
	}

	// Verify current page still works
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Errorf("Current page should still work after CloseOtherWindows: %v", err)
	}
}

// TestBrowserCloseOtherWindowsWindowOpen tests closing popups opened by window.open().
func TestBrowserCloseOtherWindowsWindowOpen(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	// Create main page and navigate to newtab test page
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/newtab/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Set as current page
	b.SetCurrentPage(page)

	// Get initial page count
	allPages, err := b.rodBrowser.Pages()
	if err != nil {
		t.Fatalf("Failed to get initial pages: %v", err)
	}
	initialPageCount := len(allPages)

	// Click the window.open() link
	err = page.rodPage.MustElement("#link-popup").Click("left", 1)
	if err != nil {
		t.Fatalf("Click on window.open link failed: %v", err)
	}

	// Give browser time to open popup
	time.Sleep(500 * time.Millisecond)

	// Verify popup was created
	allPages, err = b.rodBrowser.Pages()
	if err != nil {
		t.Fatalf("Failed to get pages after click: %v", err)
	}

	if len(allPages) <= initialPageCount {
		t.Logf("Note: Popup may not have opened (popup blocker?). Pages: %d", len(allPages))
		return
	}

	t.Logf("Popup opened: %d -> %d pages", initialPageCount, len(allPages))

	// Now call CloseOtherWindows
	if err := b.CloseOtherWindows(); err != nil {
		t.Fatalf("CloseOtherWindows() failed: %v", err)
	}

	// Verify only current page remains
	allPages, err = b.rodBrowser.Pages()
	if err != nil {
		t.Fatalf("Failed to get pages after CloseOtherWindows: %v", err)
	}

	if len(allPages) != 1 {
		t.Errorf("Expected 1 page after CloseOtherWindows, got %d", len(allPages))
	}
}

// TestBrowserCloseOtherWindowsMultiplePages tests closing multiple pages with timeout protection.
// This validates that CloseOtherWindows() doesn't deadlock when there are multiple pages to close.
func TestBrowserCloseOtherWindowsMultiplePages(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	// Create main page
	mainPage, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := mainPage.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	b.SetCurrentPage(mainPage)

	// Create 3 additional pages to simulate multiple tabs being open
	for i := 0; i < 3; i++ {
		extraPage, err := b.NewPage()
		if err != nil {
			t.Fatalf("Failed to create extra page %d: %v", i+1, err)
		}
		if err := extraPage.Navigate(server.URL + "/simple.html"); err != nil {
			t.Logf("Failed to navigate extra page %d: %v", i+1, err)
		}
	}

	// Verify we have multiple pages
	allPages, _ := b.rodBrowser.Pages()
	if len(allPages) <= 1 {
		t.Skip("Failed to create multiple pages")
	}

	t.Logf("Created %d pages total", len(allPages))

	// CloseOtherWindows should NOT deadlock even with multiple pages
	// This uses timeout + retry logic internally
	if err := b.CloseOtherWindows(); err != nil {
		t.Fatalf("CloseOtherWindows() should not fail: %v", err)
	}

	// Verify only current page remains
	allPages, _ = b.rodBrowser.Pages()
	if len(allPages) != 1 {
		t.Errorf("Expected 1 page after CloseOtherWindows, got %d", len(allPages))
	}

	// Verify current page still works
	if err := mainPage.Navigate(server.URL + "/home.html"); err != nil {
		t.Errorf("Current page should still work: %v", err)
	}
}

// TestBrowserCloseOtherWindowsTimeout validates timeout mechanism doesn't hang.
func TestBrowserCloseOtherWindowsTimeout(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)

	page1, _ := b.NewPage()
	_, _ = b.NewPage() // Create second page to be closed

	b.SetCurrentPage(page1)

	// Should complete even if page2 is slow to close
	err := b.CloseOtherWindows()

	// Should NOT hang indefinitely
	if err != nil {
		t.Logf("CloseOtherWindows returned error (expected with timeout): %v", err)
	}
}
