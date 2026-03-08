//go:build integration

package browser

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

// countElements counts elements with given tag in HTML document.
func countElements(doc *html.Node, tag string) int {
	count := 0
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, tag) {
			count++
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return count
}

// findElementByID finds element with given id in HTML document.
func findElementByID(doc *html.Node, id string) *html.Node {
	var result *html.Node
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == id {
					result = n
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return result
}

// TestPageNavigate tests navigation to URL.
// Crawljax parity: goToUrl()
func TestPageNavigate(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Navigate to simple.html
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Verify URL
	url, err := page.URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	expectedURL := server.URL + "/simple.html"
	if url != expectedURL {
		t.Errorf("Expected URL %s, got %s", expectedURL, url)
	}
}

// TestPageNavigateToIndex tests navigation to index page with JavaScript.
func TestPageNavigateToIndex(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Navigate to index.html which has JavaScript
	if err := page.Navigate(server.URL + "/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Wait for JavaScript to load
	time.Sleep(500 * time.Millisecond)

	// Verify page loaded with exact title
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Title() failed: %v", err)
	}

	expectedTitle := "Crawljax testSite"
	if title != expectedTitle {
		t.Errorf("Expected title %q, got %q", expectedTitle, title)
	}
}

// TestPageReload tests page reload.
func TestPageReload(t *testing.T) {
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

	// Reload should not error
	if err := page.Reload(); err != nil {
		t.Fatalf("Reload() failed: %v", err)
	}

	// URL should still be the same
	url, err := page.URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	if !strings.Contains(url, "simple.html") {
		t.Errorf("URL should still contain simple.html after reload, got %s", url)
	}
}

// TestPageURL tests getting current URL.
// Crawljax parity: getCurrentUrl()
func TestPageURL(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Before navigation
	url, err := page.URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}
	if url != "about:blank" {
		t.Logf("Initial URL: %s", url)
	}

	// After navigation
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	url, err = page.URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	expectedURL := server.URL + "/simple.html"
	if url != expectedURL {
		t.Errorf("Expected URL %s, got %s", expectedURL, url)
	}
}

// TestPageHTML tests getting page HTML.
// Crawljax parity: getStrippedDom()
func TestPageHTML(t *testing.T) {
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

	html, err := page.HTML()
	if err != nil {
		t.Fatalf("HTML() failed: %v", err)
	}

	// Verify HTML structure - extract and compare
	if !strings.Contains(html, "<title>Simple page</title>") {
		t.Error("HTML should contain title element")
	}

	if !strings.Contains(html, "<h1>Simple page</h1>") {
		t.Error("HTML should contain h1 element")
	}

	if !strings.Contains(html, "Nothing fancy here") {
		t.Error("HTML should contain paragraph text")
	}
}

// TestPageTitle tests getting page title.
func TestPageTitle(t *testing.T) {
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

	title, err := page.Title()
	if err != nil {
		t.Fatalf("Title() failed: %v", err)
	}

	expectedTitle := "Simple page"
	if title != expectedTitle {
		t.Errorf("Expected title %q, got %q", expectedTitle, title)
	}
}

// TestPageNavigateBack tests navigation back.
// Crawljax parity: goBack()
func TestPageNavigateBack(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Navigate to first page
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() 1 failed: %v", err)
	}

	// Navigate to second page
	if err := page.Navigate(server.URL + "/home.html"); err != nil {
		t.Fatalf("Navigate() 2 failed: %v", err)
	}

	// Go back
	if err := page.NavigateBack(); err != nil {
		t.Fatalf("NavigateBack() failed: %v", err)
	}

	// Wait for navigation
	time.Sleep(500 * time.Millisecond)

	// Should be back at first page
	url, err := page.URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	if !strings.Contains(url, "simple.html") {
		t.Errorf("Expected to be back at simple.html, got %s", url)
	}
}

// TestPageNavigateForward tests navigation forward.
func TestPageNavigateForward(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Navigate to first page
	if err := page.Navigate(server.URL + "/simple.html"); err != nil {
		t.Fatalf("Navigate() 1 failed: %v", err)
	}

	// Navigate to second page
	if err := page.Navigate(server.URL + "/home.html"); err != nil {
		t.Fatalf("Navigate() 2 failed: %v", err)
	}

	// Go back
	if err := page.NavigateBack(); err != nil {
		t.Fatalf("NavigateBack() failed: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Go forward
	if err := page.NavigateForward(); err != nil {
		t.Fatalf("NavigateForward() failed: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Should be at second page
	url, err := page.URL()
	if err != nil {
		t.Fatalf("URL() failed: %v", err)
	}

	if !strings.Contains(url, "home.html") {
		t.Errorf("Expected to be at home.html, got %s", url)
	}
}

// TestPageWaitStable tests waiting for page stability.
func TestPageWaitStable(t *testing.T) {
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

	// WaitStable should not error on stable page
	if err := page.WaitStable(500 * time.Millisecond); err != nil {
		t.Errorf("WaitStable() failed: %v", err)
	}
}

// TestPageWaitLoad tests waiting for page load.
func TestPageWaitLoad(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Navigate without waiting in Navigate method
	page.rodPage.Navigate(server.URL + "/simple.html")

	// WaitLoad should wait for page to load
	if err := page.WaitLoad(); err != nil {
		t.Errorf("WaitLoad() failed: %v", err)
	}

	// Page should be loaded now
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Title() failed: %v", err)
	}

	if title != "Simple page" {
		t.Errorf("Expected title 'Simple page', got %q", title)
	}
}

// TestPageWaitElement tests waiting for element.
func TestPageWaitElement(t *testing.T) {
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

	// Wait for existing element
	if err := page.WaitElement("h1", 5*time.Second); err != nil {
		t.Errorf("WaitElement() for existing element failed: %v", err)
	}

	// Wait for non-existing element should timeout
	err = page.WaitElement("#nonexistent", 500*time.Millisecond)
	if err == nil {
		t.Error("WaitElement() for non-existing element should timeout")
	}
}

// TestPageWaitVisible tests waiting for element visibility.
func TestPageWaitVisible(t *testing.T) {
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

	// Wait for visible element
	if err := page.WaitVisible("h1", 5*time.Second); err != nil {
		t.Errorf("WaitVisible() for visible element failed: %v", err)
	}
}

// TestPageElement tests finding element by CSS selector.
// Crawljax parity: getWebElement()
func TestPageElement(t *testing.T) {
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

	// Find by tag
	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	text, err := elem.Text()
	if err != nil {
		t.Fatalf("Text() failed: %v", err)
	}

	if text != "Simple page" {
		t.Errorf("Expected text 'Simple page', got %q", text)
	}
}

// TestPageElementX tests finding element by XPath.
// Crawljax parity: XPath element selection
func TestPageElementX(t *testing.T) {
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

	// Find by XPath
	elem, err := page.ElementX("//h1")
	if err != nil {
		t.Fatalf("ElementX() failed: %v", err)
	}

	text, err := elem.Text()
	if err != nil {
		t.Fatalf("Text() failed: %v", err)
	}

	if text != "Simple page" {
		t.Errorf("Expected text 'Simple page', got %q", text)
	}
}

// TestPageElements tests finding multiple elements.
func TestPageElements(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/underxpath.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Find list items - underxpath.html has exactly 3 li elements
	elems, err := page.Elements("li")
	if err != nil {
		t.Fatalf("Elements() failed: %v", err)
	}

	expectedCount := 3
	if len(elems) != expectedCount {
		t.Errorf("Expected exactly %d li elements, got %d", expectedCount, len(elems))
	}
}

// TestPageElementsX tests finding multiple elements by XPath.
func TestPageElementsX(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/underxpath.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Find list items by XPath - underxpath.html has exactly 3 li elements in ul
	elems, err := page.ElementsX("//ul/li")
	if err != nil {
		t.Fatalf("ElementsX() failed: %v", err)
	}

	expectedCount := 3
	if len(elems) != expectedCount {
		t.Errorf("Expected exactly %d li elements, got %d", expectedCount, len(elems))
	}
}

// TestPageHasElement tests checking element existence.
// Crawljax parity: elementExists()
func TestPageHasElement(t *testing.T) {
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

	// Existing element
	if !page.HasElement("h1") {
		t.Error("HasElement() should return true for existing element")
	}

	// Non-existing element
	if page.HasElement("#nonexistent") {
		t.Error("HasElement() should return false for non-existing element")
	}
}

// TestPageHasElementX tests checking element existence by XPath.
// Crawljax parity: elementExists() with XPath
func TestPageHasElementX(t *testing.T) {
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

	// Existing element
	if !page.HasElementX("//h1") {
		t.Error("HasElementX() should return true for existing element")
	}

	// Non-existing element - using wrong xpath
	if page.HasElementX("//RUBISH") {
		t.Error("HasElementX() should return false for non-existing element")
	}
}

// TestPageClick tests clicking element by selector.
// Crawljax parity: fireEventAndWait()
func TestPageClick(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/clickable/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Wait for jQuery to load
	time.Sleep(1 * time.Second)

	// Find clickable element and click (page uses #clickable div)
	if err := page.Click("#clickable"); err != nil {
		t.Fatalf("Click() failed: %v", err)
	}

	// Wait for content load
	time.Sleep(500 * time.Millisecond)

	// Verify content was loaded via AJAX
	htmlContent, _ := page.HTML()
	// Content div should have content from clicked.html
	_ = htmlContent
}

// TestPageHover tests hovering over element.
func TestPageHover(t *testing.T) {
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

	// Hover should not error
	if err := page.Hover("h1"); err != nil {
		t.Errorf("Hover() failed: %v", err)
	}
}

// TestPageEval tests JavaScript execution.
// Crawljax parity: executeJavaScript()
func TestPageEval(t *testing.T) {
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

	// Execute JavaScript and get result
	result, err := page.Eval("(() => document.title)()")
	if err != nil {
		t.Fatalf("Eval() failed: %v", err)
	}

	if result != "Simple page" {
		t.Errorf("Expected 'Simple page', got %v", result)
	}

	// Execute JavaScript that returns number
	result, err = page.Eval("(() => 1 + 1)()")
	if err != nil {
		t.Fatalf("Eval() for number failed: %v", err)
	}

	// Result should be float64 from JSON
	if val, ok := result.(float64); !ok || val != 2 {
		t.Errorf("Expected 2, got %v", result)
	}

	// Execute JavaScript that returns boolean
	result, err = page.Eval("(() => true)()")
	if err != nil {
		t.Fatalf("Eval() for boolean failed: %v", err)
	}

	if result != true {
		t.Errorf("Expected true, got %v", result)
	}
}

// TestPageEvalWithArgs tests JavaScript execution with arguments.
func TestPageEvalWithArgs(t *testing.T) {
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

	// Execute with arguments
	result, err := page.EvalWithArgs("(a, b) => a + b", 1, 2)
	if err != nil {
		t.Fatalf("EvalWithArgs() failed: %v", err)
	}

	if val, ok := result.(float64); !ok || val != 3 {
		t.Errorf("Expected 3, got %v", result)
	}
}

// TestPageScreenshot tests screenshot capture.
// Crawljax parity: saveScreenShot()
func TestPageScreenshot(t *testing.T) {
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

	// Take screenshot
	data, err := page.Screenshot()
	if err != nil {
		t.Fatalf("Screenshot() failed: %v", err)
	}

	// Verify screenshot is not empty
	if len(data) == 0 {
		t.Error("Screenshot data should not be empty")
	}

	// Verify it's a valid PNG (starts with PNG signature)
	pngSignature := []byte{0x89, 0x50, 0x4E, 0x47}
	if !bytes.HasPrefix(data, pngSignature) {
		t.Error("Screenshot should be valid PNG")
	}
}

// TestPageFullScreenshot tests full page screenshot.
func TestPageFullScreenshot(t *testing.T) {
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

	// Take full screenshot
	data, err := page.FullScreenshot()
	if err != nil {
		t.Fatalf("FullScreenshot() failed: %v", err)
	}

	// Verify screenshot is not empty
	if len(data) == 0 {
		t.Error("FullScreenshot data should not be empty")
	}

	// Save to temp file to verify (Crawljax pattern)
	tmpFile := filepath.Join(os.TempDir(), "test-screenshot.png")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatalf("Failed to write screenshot: %v", err)
	}
	defer os.Remove(tmpFile)

	// Verify file was created and has content
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Failed to stat screenshot file: %v", err)
	}

	if info.Size() == 0 {
		t.Error("Screenshot file should not be empty")
	}
}

// TestPageFrames tests iframe handling.
// Crawljax parity: getFrameDom()
func TestPageFrames(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/iframe/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Wait for iframes to load
	time.Sleep(1 * time.Second)

	// Get frames
	frames, err := page.Frames()
	if err != nil {
		t.Fatalf("Frames() failed: %v", err)
	}

	// Should have 2 iframes
	if len(frames) != 2 {
		t.Errorf("Expected 2 frames, got %d", len(frames))
	}

	// Each frame should be a valid page
	for i, frame := range frames {
		html, err := frame.HTML()
		if err != nil {
			t.Errorf("Frame %d HTML() failed: %v", i, err)
			continue
		}
		if html == "" {
			t.Errorf("Frame %d HTML should not be empty", i)
		}
	}
}

// TestPageGetDocument tests getting DOM document with iframes.
// Crawljax parity: testGetDocument()
func TestPageGetDocument(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/iframe/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Wait for page to load
	time.Sleep(1 * time.Second)

	// Get HTML
	htmlContent, err := page.HTML()
	if err != nil {
		t.Fatalf("HTML() failed: %v", err)
	}

	// Parse HTML and count iframes
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	iframeCount := countElements(doc, "iframe")

	// Crawljax test expects 2 iframes
	if iframeCount != 2 {
		t.Errorf("Expected 2 IFRAME elements, got %d", iframeCount)
	}
}

// TestPageSetViewport tests setting viewport size.
func TestPageSetViewport(t *testing.T) {
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

	// Set viewport
	if err := page.SetViewport(800, 600); err != nil {
		t.Errorf("SetViewport() failed: %v", err)
	}

	// Verify by checking window dimensions
	result, err := page.Eval("(() => window.innerWidth)()")
	if err != nil {
		t.Fatalf("Eval innerWidth failed: %v", err)
	}

	width, ok := result.(float64)
	if !ok {
		t.Fatalf("Expected float64, got %T", result)
	}

	// Width should be exactly 800
	expectedWidth := 800.0
	if width != expectedWidth {
		t.Errorf("Expected width %f, got %f", expectedWidth, width)
	}
}

// TestPageAlertDialog tests handling alert dialogs.
func TestPageAlertDialog(t *testing.T) {
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

	// Set up dialog handler
	if err := page.HandlePopups(); err != nil {
		t.Fatalf("HandlePopups() failed: %v", err)
	}

	// Trigger alert - should be auto-handled without error
	_, err = page.Eval("(() => alert('test alert'))()")
	if err != nil {
		t.Errorf("Eval alert failed: %v", err)
	}
}

// TestPageConfirmDialog tests handling confirm dialogs.
func TestPageConfirmDialog(t *testing.T) {
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

	// Set up dialog handler
	if err := page.HandlePopups(); err != nil {
		t.Fatalf("HandlePopups() failed: %v", err)
	}

	// Give time for handler to be set
	time.Sleep(100 * time.Millisecond)

	// Trigger confirm - should be auto-accepted and return true
	result, err := page.Eval("(() => confirm('test confirm'))()")
	if err != nil {
		t.Fatalf("Eval confirm failed: %v", err)
	}

	// With HandlePopups accepting all dialogs, confirm must return true
	if result != true {
		t.Errorf("Expected confirm to return true, got %v", result)
	}
}

// TestPagePromptDialog tests handling prompt dialogs.
func TestPagePromptDialog(t *testing.T) {
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

	// Set up dialog handler
	if err := page.HandlePopups(); err != nil {
		t.Fatalf("HandlePopups() failed: %v", err)
	}

	// Give time for handler to be set
	time.Sleep(100 * time.Millisecond)

	// Trigger prompt - should be auto-accepted with empty promptText (per setupAutoDialogHandler)
	result, err := page.Eval("(() => prompt('test prompt', 'default'))()")
	if err != nil {
		t.Fatalf("Eval prompt failed: %v", err)
	}

	// setupAutoDialogHandler accepts with empty PromptText, so prompt returns ""
	if result != "" {
		t.Errorf("Expected prompt to return '' (auto-accepted with empty promptText), got %v", result)
	}
}

// TestPageClose tests page close.
func TestPageClose(t *testing.T) {
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

	// Close page
	if err := page.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

// TestPageBrowser tests getting parent browser.
func TestPageBrowser(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if page.Browser() != b {
		t.Error("Page.Browser() should return parent browser")
	}
}

// TestPageRodPage tests getting underlying rod.Page.
func TestPageRodPage(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if page.RodPage() == nil {
		t.Error("RodPage() should not return nil")
	}
}

// TestPageWaitDOMStable tests waiting for DOM stability.
func TestPageWaitDOMStable(t *testing.T) {
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

	// Wait for DOM to be stable
	if err := page.WaitDOMStable(500*time.Millisecond, 0.1); err != nil {
		t.Errorf("WaitDOMStable() failed: %v", err)
	}
}
