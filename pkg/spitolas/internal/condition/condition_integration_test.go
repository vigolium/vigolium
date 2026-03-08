//go:build integration

package condition

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// setupTestServer creates a test server serving files from testdata directory.
func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.FileServer(http.Dir("testdata")))
}

// setupBrowser creates a browser for integration tests using config.
func setupBrowser(t *testing.T, serverURL string) *browser.Browser {
	t.Helper()
	cfg, err := config.New(serverURL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	b, err := browser.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create browser: %v", err)
	}
	t.Cleanup(func() {
		b.Close()
	})
	return b
}

// TestIntegrationURLContains tests URL condition with real browser.
func TestIntegrationURLContains(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Test URL contains
	cond := URLContains("testInvariants")
	if !cond.Check(page) {
		t.Error("URLContains should match")
	}

	cond2 := URLContains("nonexistent")
	if cond2.Check(page) {
		t.Error("URLContains should not match")
	}
}

// TestIntegrationURLMatches tests URL regex with real browser.
func TestIntegrationURLMatches(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Test URL regex
	cond := URLMatches(`.*testInvariants\.html$`)
	if !cond.Check(page) {
		t.Error("URLMatches should match")
	}

	cond2 := URLMatches(`.*other\.html$`)
	if cond2.Check(page) {
		t.Error("URLMatches should not match")
	}
}

// TestIntegrationElementExists tests element existence with real browser.
func TestIntegrationElementExists(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Element exists
	cond := ElementExists("#SHOULD_ALWAYS_BE_ON_THIS_PAGE")
	if !cond.Check(page) {
		t.Error("ElementExists should match existing element")
	}

	// Element does not exist
	cond2 := ElementExists("#nonexistent")
	if cond2.Check(page) {
		t.Error("ElementExists should not match non-existing element")
	}
}

// TestIntegrationDOMRegex tests DOM regex matching with real browser.
func TestIntegrationDOMRegex(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testCrawlconditions.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Should find DONT_CRAWL_ME in page
	cond := DOMRegex("DONT_CRAWL_ME")
	if !cond.Check(page) {
		t.Error("DOMRegex should find DONT_CRAWL_ME")
	}

	// Should not find random text
	cond2 := DOMRegex("RANDOM_TEXT_NOT_IN_PAGE")
	if cond2.Check(page) {
		t.Error("DOMRegex should not match random text")
	}
}

// TestIntegrationXPathExists tests XPath condition with real browser.
func TestIntegrationXPathExists(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/underxpath.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Find list items
	cond := XPathExists("//ul/li")
	if !cond.Check(page) {
		t.Error("XPathExists should find list items")
	}

	// Find specific element by id
	cond2 := XPathExists("//a[@id='noClickId']")
	if !cond2.Check(page) {
		t.Error("XPathExists should find element by id")
	}

	// Should not find non-existent xpath
	cond3 := XPathExists("//nonexistent")
	if cond3.Check(page) {
		t.Error("XPathExists should not match non-existent path")
	}
}

// TestIntegrationJavaScript tests JavaScript condition with real browser.
func TestIntegrationJavaScript(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Document ready check
	cond := JavaScript(JSDocumentReady)
	if !cond.Check(page) {
		t.Error("JSDocumentReady should be true")
	}

	// Custom JS expression
	cond2 := JavaScript("document.getElementById('INVARIANT_VIOLATION') !== null")
	if !cond2.Check(page) {
		t.Error("JS should find element")
	}

	// False condition
	cond3 := JavaScript("false")
	if cond3.Check(page) {
		t.Error("JS false should return false")
	}
}

// TestIntegrationCompositeConditions tests composite conditions with real browser.
func TestIntegrationCompositeConditions(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// AND condition - all must pass
	andCond := And(
		URLContains("testInvariants"),
		ElementExists("#SHOULD_ALWAYS_BE_ON_THIS_PAGE"),
		JavaScript("true"),
	)
	if !andCond.Check(page) {
		t.Error("AND condition should pass when all true")
	}

	// AND with one false
	andCond2 := And(
		URLContains("testInvariants"),
		ElementExists("#nonexistent"),
	)
	if andCond2.Check(page) {
		t.Error("AND condition should fail when one false")
	}

	// OR condition - at least one must pass
	orCond := Or(
		ElementExists("#nonexistent"),
		ElementExists("#SHOULD_ALWAYS_BE_ON_THIS_PAGE"),
	)
	if !orCond.Check(page) {
		t.Error("OR condition should pass when one true")
	}

	// OR with all false
	orCond2 := Or(
		ElementExists("#nonexistent1"),
		ElementExists("#nonexistent2"),
	)
	if orCond2.Check(page) {
		t.Error("OR condition should fail when all false")
	}
}

// TestIntegrationNegation tests negated conditions with real browser.
func TestIntegrationNegation(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Negated true becomes false
	cond := URLContains("testInvariants").Not()
	if cond.Check(page) {
		t.Error("Negated true condition should return false")
	}

	// Negated false becomes true
	cond2 := URLContains("nonexistent").Not()
	if !cond2.Check(page) {
		t.Error("Negated false condition should return true")
	}
}

// TestIntegrationUnderpathXPath tests XPath scoping with real browser.
// Uses underxpath.html from Crawljax test fixtures.
func TestIntegrationUnderpathXPath(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	b := setupBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/underxpath.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	tests := []struct {
		name   string
		xpath  string
		exists bool
	}{
		{"list exists", "//ul", true},
		{"list items exist", "//ul/li", true},
		{"noClickId element", "//a[@id='noClickId']", true},
		{"noClickClass element", "//a[@class='noClickClass']", true},
		{"noChildrenOfId div", "//div[@id='noChildrenOfId']", true},
		{"noChildrenOfClass div", "//div[@class='noChildrenOfClass']", true},
		{"container exists", "//p[@id='container']", true},
		{"nonexistent", "//span[@id='nonexistent']", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := XPathExists(tt.xpath)
			got := cond.Check(page)
			if got != tt.exists {
				t.Errorf("XPathExists(%q) = %v, want %v", tt.xpath, got, tt.exists)
			}
		})
	}
}
