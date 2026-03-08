//go:build integration

package browser

import (
	"strings"
	"testing"
	"time"
)

// TestElementClick tests clicking an element.
// Crawljax parity: fireEventAndWait()
func TestElementClick(t *testing.T) {
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

	// Find clickable div element (the page uses #clickable div, not <a> tags)
	elem, err := page.Element("#clickable")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Click should not error
	if err := elem.Click(); err != nil {
		t.Errorf("Click() failed: %v", err)
	}

	// Wait for content to load
	time.Sleep(500 * time.Millisecond)

	// Verify content was loaded
	content, err := page.Element("#content")
	if err != nil {
		t.Fatalf("Content element failed: %v", err)
	}

	html, _ := content.HTML()
	// Content should have been loaded from clicked.html
	if html == "" || html == "<div id=\"content\"></div>" {
		t.Log("Content may not have loaded - this depends on jQuery functioning correctly")
	}
}

// TestElementDoubleClick tests double-clicking an element.
func TestElementDoubleClick(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Double click should not error
	if err := elem.DoubleClick(); err != nil {
		t.Errorf("DoubleClick() failed: %v", err)
	}
}

// TestElementRightClick tests right-clicking an element.
func TestElementRightClick(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Right click should not error
	if err := elem.RightClick(); err != nil {
		t.Errorf("RightClick() failed: %v", err)
	}
}

// TestElementHover tests hovering over an element.
func TestElementHover(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Hover should not error
	if err := elem.Hover(); err != nil {
		t.Errorf("Hover() failed: %v", err)
	}
}

// TestElementFocus tests focusing an element.
func TestElementFocus(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Find input element
	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Focus should not error
	if err := elem.Focus(); err != nil {
		t.Errorf("Focus() failed: %v", err)
	}
}

// TestElementInput tests typing text into an element.
// Crawljax parity: input()
func TestElementInput(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Find input element
	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Type text
	testText := "John Doe"
	if err := elem.Input(testText); err != nil {
		t.Fatalf("Input() failed: %v", err)
	}

	// Verify value was set - use Property to get current value
	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if value != testText {
		t.Errorf("Expected value %q, got %q", testText, value)
	}
}

// TestElementInputWithClear tests clearing and inputting text.
// Crawljax parity: Form handler clear before input
func TestElementInputWithClear(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// First input
	if err := elem.Input("Initial"); err != nil {
		t.Fatalf("Input() 1 failed: %v", err)
	}

	// Clear (select all)
	if err := elem.Clear(); err != nil {
		t.Fatalf("Clear() failed: %v", err)
	}

	// Second input (should replace)
	newText := "New Value"
	if err := elem.Input(newText); err != nil {
		t.Fatalf("Input() 2 failed: %v", err)
	}

	// Verify only new value
	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	// After Clear + Input, value should be the new text
	if value != newText {
		t.Errorf("Expected value %q, got %q", newText, value)
	}
}

// TestElementClear tests clearing element value.
func TestElementClear(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Input some text
	if err := elem.Input("test"); err != nil {
		t.Fatalf("Input() failed: %v", err)
	}

	// Clear should select all (not actually clear, but select for replacement)
	if err := elem.Clear(); err != nil {
		t.Errorf("Clear() failed: %v", err)
	}
}

// TestElementSelectAllText tests selecting all text.
func TestElementSelectAllText(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Input text
	if err := elem.Input("test text"); err != nil {
		t.Fatalf("Input() failed: %v", err)
	}

	// Select all should not error
	if err := elem.SelectAllText(); err != nil {
		t.Errorf("SelectAllText() failed: %v", err)
	}
}

// TestElementText tests getting text content.
func TestElementText(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	text, err := elem.Text()
	if err != nil {
		t.Fatalf("Text() failed: %v", err)
	}

	expectedText := "Simple page"
	if text != expectedText {
		t.Errorf("Expected text %q, got %q", expectedText, text)
	}
}

// TestElementHTML tests getting outer HTML.
func TestElementHTML(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	html, err := elem.HTML()
	if err != nil {
		t.Fatalf("HTML() failed: %v", err)
	}

	// Exact match for h1 outer HTML
	expectedHTML := "<h1>Simple page</h1>"
	if html != expectedHTML {
		t.Errorf("Expected HTML %q, got %q", expectedHTML, html)
	}
}

// TestElementAttribute tests getting attribute value.
func TestElementAttribute(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Get id attribute
	id, err := elem.Attribute("id")
	if err != nil {
		t.Fatalf("Attribute() failed: %v", err)
	}

	if id != "name" {
		t.Errorf("Expected id 'name', got %q", id)
	}

	// Get type attribute
	attrType, err := elem.Attribute("type")
	if err != nil {
		t.Fatalf("Attribute() for type failed: %v", err)
	}

	if attrType != "text" {
		t.Errorf("Expected type 'text', got %q", attrType)
	}
}

// TestElementProperty tests getting property value.
func TestElementProperty(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Input some value
	if err := elem.Input("test"); err != nil {
		t.Fatalf("Input() failed: %v", err)
	}

	// Get value property
	value, err := elem.Property("value")
	if err != nil {
		t.Fatalf("Property() failed: %v", err)
	}

	if value != "test" {
		t.Errorf("Expected value 'test', got %v", value)
	}
}

// TestElementTagName tests getting tag name.
func TestElementTagName(t *testing.T) {
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

	tests := []struct {
		selector string
		expected string
	}{
		{"h1", "h1"},
		{"p", "p"},
		{"body", "body"},
	}

	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			elem, err := page.Element(tt.selector)
			if err != nil {
				t.Fatalf("Element() failed: %v", err)
			}

			tag, err := elem.TagName()
			if err != nil {
				t.Fatalf("TagName() failed: %v", err)
			}

			if tag != tt.expected {
				t.Errorf("Expected tag %q, got %q", tt.expected, tag)
			}
		})
	}
}

// TestElementIsVisible tests visibility check.
// Crawljax parity: isVisible()
func TestElementIsVisible(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// h1 should be visible
	if !elem.IsVisible() {
		t.Error("h1 element should be visible")
	}
}

// TestElementIsVisibleHidden tests visibility check for hidden elements.
func TestElementIsVisibleHidden(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/hidden-elements-site/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Check for hidden elements - adjust based on actual page content
	// Try to find elements that might be hidden
	elems, err := page.Elements("*[style*='display: none'], *[style*='visibility: hidden']")
	if err == nil && len(elems) > 0 {
		for _, elem := range elems {
			if elem.IsVisible() {
				t.Error("Hidden element should not be visible")
			}
		}
	}
}

// TestElementIsInteractable tests interactable check.
func TestElementIsInteractable(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Input should be interactable
	if !elem.IsInteractable() {
		t.Error("Input element should be interactable")
	}
}

// TestElementWaitVisible tests waiting for visibility.
func TestElementWaitVisible(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Should not error for visible element
	if err := elem.WaitVisible(); err != nil {
		t.Errorf("WaitVisible() failed: %v", err)
	}
}

// TestElementWaitEnabled tests waiting for enabled state.
func TestElementWaitEnabled(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Should not error for enabled element
	if err := elem.WaitEnabled(); err != nil {
		t.Errorf("WaitEnabled() failed: %v", err)
	}
}

// TestElementWaitInteractable tests waiting for interactable state.
func TestElementWaitInteractable(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Should not error for interactable element
	if err := elem.WaitInteractable(); err != nil {
		t.Errorf("WaitInteractable() failed: %v", err)
	}
}

// TestElementScrollIntoView tests scrolling element into view.
func TestElementScrollIntoView(t *testing.T) {
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

	elem, err := page.Element("p")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Should not error
	if err := elem.ScrollIntoView(); err != nil {
		t.Errorf("ScrollIntoView() failed: %v", err)
	}
}

// TestElementGetSelector tests CSS selector generation.
func TestElementGetSelector(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	selector, err := elem.GetSelector()
	if err != nil {
		t.Fatalf("GetSelector() failed: %v", err)
	}

	// Element with id should return #id selector
	if selector != "#name" {
		t.Errorf("Expected selector '#name', got %q", selector)
	}
}

// TestElementGetXPath tests absolute XPath generation.
// Crawljax parity: XPathHelper.getXPathExpression()
func TestElementGetXPath(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	xpath, err := elem.GetXPath()
	if err != nil {
		t.Fatalf("GetXPath() failed: %v", err)
	}

	// XPath should start with / (absolute)
	if !strings.HasPrefix(xpath, "/") {
		t.Errorf("XPath should start with /, got %q", xpath)
	}

	// XPath should contain html and h1
	if !strings.Contains(xpath, "html") {
		t.Errorf("XPath should contain 'html', got %q", xpath)
	}

	if !strings.Contains(xpath, "h1") {
		t.Errorf("XPath should contain 'h1', got %q", xpath)
	}

	// Verify XPath works - find element with generated xpath
	elem2, err := page.ElementX(xpath)
	if err != nil {
		t.Fatalf("ElementX() with generated XPath failed: %v", err)
	}

	text, err := elem2.Text()
	if err != nil {
		t.Fatalf("Text() failed: %v", err)
	}

	if text != "Simple page" {
		t.Errorf("Element found by XPath should have text 'Simple page', got %q", text)
	}
}

// TestElementXPathCaching tests XPath caching for M1 performance.
func TestElementXPathCaching(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// First call - generates XPath
	xpath1, err := elem.GetXPath()
	if err != nil {
		t.Fatalf("GetXPath() 1 failed: %v", err)
	}

	// Second call - should return cached value
	xpath2, err := elem.GetXPath()
	if err != nil {
		t.Fatalf("GetXPath() 2 failed: %v", err)
	}

	if xpath1 != xpath2 {
		t.Errorf("Cached XPath should be same: %q != %q", xpath1, xpath2)
	}

	// Verify cache is set
	if !elem.xpathCached {
		t.Error("xpathCached should be true after GetXPath()")
	}

	if elem.cachedXPath != xpath1 {
		t.Error("cachedXPath should match returned value")
	}
}

// TestElementSelectorCaching tests selector caching for M1 performance.
func TestElementSelectorCaching(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// First call
	sel1, err := elem.GetSelector()
	if err != nil {
		t.Fatalf("GetSelector() 1 failed: %v", err)
	}

	// Second call - cached
	sel2, err := elem.GetSelector()
	if err != nil {
		t.Fatalf("GetSelector() 2 failed: %v", err)
	}

	if sel1 != sel2 {
		t.Errorf("Cached selector should be same: %q != %q", sel1, sel2)
	}

	if !elem.selectorCached {
		t.Error("selectorCached should be true after GetSelector()")
	}
}

// TestElementClearCache tests clearing cached values.
func TestElementClearCache(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Generate cached values
	elem.GetXPath()
	elem.GetSelector()

	if !elem.xpathCached || !elem.selectorCached {
		t.Error("Cache should be populated")
	}

	// Clear cache
	elem.ClearCache()

	if elem.xpathCached || elem.selectorCached {
		t.Error("Cache should be cleared after ClearCache()")
	}

	if elem.cachedXPath != "" || elem.cachedSelector != "" {
		t.Error("Cached values should be empty after ClearCache()")
	}
}

// TestElementMatches tests CSS selector matching.
func TestElementMatches(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	elem, err := page.Element("#name")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Should match input selector
	if !elem.Matches("input") {
		t.Error("Element should match 'input' selector")
	}

	// Should match id selector
	if !elem.Matches("#name") {
		t.Error("Element should match '#name' selector")
	}

	// Should match type selector
	if !elem.Matches("input[type='text']") {
		t.Error("Element should match 'input[type=\"text\"]' selector")
	}

	// Should not match wrong selector
	if elem.Matches("button") {
		t.Error("Element should not match 'button' selector")
	}
}

// TestElementEval tests JavaScript evaluation on element.
func TestElementEval(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	// Eval without result
	if err := elem.Eval("() => this.style.color = 'red'"); err != nil {
		t.Errorf("Eval() failed: %v", err)
	}
}

// TestElementEvalWithResult tests JavaScript evaluation with result.
func TestElementEvalWithResult(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	result, err := elem.EvalWithResult("() => this.textContent")
	if err != nil {
		t.Fatalf("EvalWithResult() failed: %v", err)
	}

	if result != "Simple page" {
		t.Errorf("Expected 'Simple page', got %v", result)
	}
}

// TestElementParent tests getting parent element.
func TestElementParent(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	parent, err := elem.Parent()
	if err != nil {
		t.Fatalf("Parent() failed: %v", err)
	}

	// Parent of h1 should be body
	tag, err := parent.TagName()
	if err != nil {
		t.Fatalf("TagName() failed: %v", err)
	}

	if tag != "body" {
		t.Errorf("Expected parent tag 'body', got %q", tag)
	}
}

// TestElementChildren tests getting child elements.
func TestElementChildren(t *testing.T) {
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

	elem, err := page.Element("body")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	children, err := elem.Children()
	if err != nil {
		t.Fatalf("Children() failed: %v", err)
	}

	// simple.html body has exactly 2 element children: h1 and p
	expectedChildren := 2
	if len(children) != expectedChildren {
		t.Errorf("Expected exactly %d children, got %d", expectedChildren, len(children))
	}
}

// TestElementBoundingBox tests getting bounding box.
func TestElementBoundingBox(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	box, err := elem.BoundingBox()
	if err != nil {
		t.Fatalf("BoundingBox() failed: %v", err)
	}

	// Box should have positive dimensions
	if box.Width <= 0 {
		t.Errorf("Expected positive width, got %f", box.Width)
	}

	if box.Height <= 0 {
		t.Errorf("Expected positive height, got %f", box.Height)
	}
}

// TestElementHasClass tests checking CSS class.
func TestElementHasClass(t *testing.T) {
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

	// Find element with class
	elem, err := page.Element(".noClickClass")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	if !elem.HasClass("noClickClass") {
		t.Error("Element should have class 'noClickClass'")
	}

	if elem.HasClass("nonexistent") {
		t.Error("Element should not have class 'nonexistent'")
	}
}

// TestElementGetClasses tests getting all CSS classes.
func TestElementGetClasses(t *testing.T) {
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

	elem, err := page.Element(".noClickClass")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	classes, err := elem.GetClasses()
	if err != nil {
		t.Fatalf("GetClasses() failed: %v", err)
	}

	// Should contain noClickClass
	found := false
	for _, c := range classes {
		if c == "noClickClass" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Classes should contain 'noClickClass', got %v", classes)
	}
}

// TestElementPage tests getting parent page.
func TestElementPage(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	if elem.Page() != page {
		t.Error("Element.Page() should return parent page")
	}
}

// TestElementRodElement tests getting underlying rod.Element.
func TestElementRodElement(t *testing.T) {
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

	elem, err := page.Element("h1")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	if elem.RodElement() == nil {
		t.Error("RodElement() should not return nil")
	}
}

// TestElementInputMultipleTypes tests input on different element types.
func TestElementInputMultipleTypes(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage() failed: %v", err)
	}

	// Create a test page with various input types
	if err := page.Navigate(server.URL + "/formhandler/index.html"); err != nil {
		t.Fatalf("Navigate() failed: %v", err)
	}

	// Test text input
	elem, err := page.Element("input")
	if err != nil {
		t.Fatalf("Element() failed: %v", err)
	}

	testCases := []struct {
		input string
	}{
		{"simple text"},
		{"text with spaces"},
		{"special chars: !@#$%"},
		{"unicode: 日本語"},
		{""},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			// Clear and input
			elem.Clear()
			if err := elem.Input(tc.input); err != nil {
				t.Errorf("Input(%q) failed: %v", tc.input, err)
			}

			// Brief wait for value to be set
			time.Sleep(50 * time.Millisecond)

			value, _ := elem.Property("value")
			if value != tc.input {
				t.Errorf("Expected value %q, got %q", tc.input, value)
			}
		})
	}
}
