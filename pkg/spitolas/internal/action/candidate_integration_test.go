//go:build integration

package action

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// =============================================================================
// CRAWLJAX PARITY: CandidateElementExtractorTest.java
// Integration tests with exact count assertions matching Crawljax
// =============================================================================

// getProjectRoot returns project root for test data access.
func getProjectRoot() string {
	// Go up from internal/action to project root
	return filepath.Join("..", "..")
}

// setupDemoSiteServer creates a test server serving demo-site files.
func setupDemoSiteServer() *httptest.Server {
	baseDir := filepath.Join(getProjectRoot(), "testdata", "html", "demo-site")
	return httptest.NewServer(http.FileServer(http.Dir(baseDir)))
}

// setupSiteServer creates a test server serving site files.
func setupSiteServer() *httptest.Server {
	baseDir := filepath.Join(getProjectRoot(), "testdata", "html", "site")
	mux := http.NewServeMux()
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	siteServer := http.FileServer(http.Dir(baseDir))
	mux.Handle("/", siteServer)
	return httptest.NewServer(mux)
}

// setupTestBrowser creates a headless browser for tests.
func setupTestBrowser(t *testing.T, serverURL string) *browser.Browser {
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

// TestExtractDemoSite tests extraction from demo-site index.
// Crawljax parity: CandidateElementExtractorTest.testExtract()
// Expected: NUMBER_OF_CANDIDATES = 15
func TestExtractDemoSite(t *testing.T) {
	const (
		// Crawljax exact value from CandidateElementExtractorTest.java
		// assertEquals(15, candidates.size())
		NUMBER_OF_CANDIDATES = 15
	)

	server := setupDemoSiteServer()
	defer server.Close()

	b := setupTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/index.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	cfg, _ := config.New(server.URL)
	extractor := NewCandidateElementExtractor(cfg)
	// Crawljax: builder.crawlRules().click("a")
	extractor.SetClickSelectors([]string{"a"})
	// CRAWLJAX PARITY: testExtract() does NOT use clickElementsWithClickEventHandler()
	// so CDP detection is disabled by default in Crawljax
	extractor.EnableCDP(false)

	ctx := context.Background()
	actions, err := extractor.Extract(ctx, page)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Crawljax parity: assertEquals(15, candidates.size())
	if len(actions) != NUMBER_OF_CANDIDATES {
		t.Errorf("len(actions) = %d, want %d (Crawljax: assertEquals)",
			len(actions), NUMBER_OF_CANDIDATES)
	}
}

// TestExtractDemoSiteExcludeMenubar tests extraction with exclusions.
// Crawljax parity: CandidateElementExtractorTest.testExtractExclude()
// Expected: NUMBER_OF_CANDIDATES = 11
func TestExtractDemoSiteExcludeMenubar(t *testing.T) {
	const (
		// Crawljax exact value from CandidateElementExtractorTest.java
		// assertThat(candidates, hasSize(11))
		NUMBER_OF_CANDIDATES = 11
	)

	server := setupDemoSiteServer()
	defer server.Close()

	b := setupTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/index.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	cfg, _ := config.New(server.URL)
	extractor := NewCandidateElementExtractor(cfg)
	// Crawljax: builder.crawlRules().click("a")
	extractor.SetClickSelectors([]string{"a"})
	// Crawljax: builder.crawlRules().dontClick("div").withAttribute("id", "menubar")
	extractor.AddExcludeSelector("#menubar")
	extractor.AddExcludeSelector("#menubar a")
	// CRAWLJAX PARITY: testExtractExclude() does NOT use clickElementsWithClickEventHandler()
	extractor.EnableCDP(false)

	ctx := context.Background()
	actions, err := extractor.Extract(ctx, page)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Crawljax parity: assertThat(candidates, hasSize(11))
	if len(actions) != NUMBER_OF_CANDIDATES {
		t.Errorf("len(actions) = %d, want %d (Crawljax: hasSize)",
			len(actions), NUMBER_OF_CANDIDATES)
	}
}

// TestExtractIframeContents tests extraction from iframes.
// Crawljax parity: CandidateElementExtractorTest.testExtractIframeContents()
// Expected: NUMBER_OF_CANDIDATES = 9
func TestExtractIframeContents(t *testing.T) {
	const (
		// Crawljax exact value from CandidateElementExtractorTest.java
		// assertThat(candidates, hasSize(9))
		NUMBER_OF_CANDIDATES = 9
	)

	server := setupSiteServer()
	defer server.Close()

	b := setupTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/iframe/"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	cfg, _ := config.New(server.URL)
	cfg.CrawlFrames = true
	extractor := NewCandidateElementExtractor(cfg)
	// Crawljax: builder.crawlRules().click("a")
	extractor.SetClickSelectors([]string{"a"})
	// CRAWLJAX PARITY: testExtractIframeContents() does NOT use clickElementsWithClickEventHandler()
	extractor.EnableCDP(false)

	ctx := context.Background()
	actions, err := extractor.Extract(ctx, page)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Crawljax parity: assertThat(candidates, hasSize(9))
	if len(actions) != NUMBER_OF_CANDIDATES {
		t.Errorf("len(actions) = %d, want %d (Crawljax: hasSize)",
			len(actions), NUMBER_OF_CANDIDATES)
	}
}

// TestExtractClickablesWithCDP tests CDP-based clickable detection.
// Crawljax parity: CandidateElementExtractorTest.testExtractClickables()
// Expected: NUMBER_OF_CANDIDATES = 1
func TestExtractClickablesWithCDP(t *testing.T) {
	const (
		// Crawljax exact value from CandidateElementExtractorTest.java
		// assertEquals(1, candidates.size())
		NUMBER_OF_CANDIDATES = 1
	)

	server := setupDemoSiteServer()
	defer server.Close()

	b := setupTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	// Navigate to clickable directory
	if err := page.Navigate(server.URL + "/clickable/"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Wait for jQuery to attach event handlers
	if err := page.WaitStable(1000); err != nil {
		t.Logf("WaitStable: %v", err)
	}

	cfg, _ := config.New(server.URL)
	extractor := NewCandidateElementExtractor(cfg)
	// Crawljax: builder.crawlRules().clickElementsWithClickEventHandler()
	extractor.EnableCDP(true)
	// Only look for elements with click handlers
	extractor.SetClickSelectors(nil) // No CSS selectors, only CDP detection

	ctx := context.Background()
	actions, err := extractor.Extract(ctx, page)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Crawljax parity: assertEquals(1, candidates.size())
	if len(actions) != NUMBER_OF_CANDIDATES {
		t.Errorf("len(actions) = %d, want %d (Crawljax: assertEquals)",
			len(actions), NUMBER_OF_CANDIDATES)
	}
}

// TestExtractNoFollowExternal tests that external links are excluded.
// Crawljax parity: CandidateElementExtractorTest.whenNoFollowExternalUrlDoNotFollow()
// Expected: NUMBER_OF_CANDIDATES = 2 (internal links only)
func TestExtractNoFollowExternal(t *testing.T) {
	const (
		// Crawljax exact value from CandidateElementExtractorTest.java
		// assertThat(extract, hasSize(2))
		NUMBER_OF_CANDIDATES = 2
	)

	// Create test HTML server with the specific test file
	htmlContent := `<!DOCTYPE html>
<html>
<body>
<a href="/internal1">Internal 1</a>
<a href="/internal2">Internal 2</a>
<a href="http://another.host.com/external">External</a>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlContent))
	}))
	defer server.Close()

	b := setupTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	cfg, _ := config.New(server.URL)
	extractor := NewCandidateElementExtractor(cfg)
	extractor.SetClickSelectors([]string{"a"})
	// Crawljax: default followExternalLinks() is false
	extractor.SetFollowExternalLinks(false)

	ctx := context.Background()
	actions, err := extractor.Extract(ctx, page)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Crawljax parity: assertThat(extract, hasSize(2))
	if len(actions) != NUMBER_OF_CANDIDATES {
		t.Errorf("len(actions) = %d, want %d (Crawljax: hasSize)",
			len(actions), NUMBER_OF_CANDIDATES)
	}
}

// TestExtractFollowExternal tests that external links are included when enabled.
// Crawljax parity: CandidateElementExtractorTest.whenFollowExternalUrlDoFollow()
// Expected: NUMBER_OF_CANDIDATES = 3 (all links)
func TestExtractFollowExternal(t *testing.T) {
	const (
		// Crawljax exact value from CandidateElementExtractorTest.java
		// assertThat(extract, hasSize(3))
		NUMBER_OF_CANDIDATES = 3
	)

	// Create test HTML server with the specific test file
	htmlContent := `<!DOCTYPE html>
<html>
<body>
<a href="/internal1">Internal 1</a>
<a href="/internal2">Internal 2</a>
<a href="http://another.host.com/external">External</a>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlContent))
	}))
	defer server.Close()

	b := setupTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	cfg, _ := config.New(server.URL)
	extractor := NewCandidateElementExtractor(cfg)
	extractor.SetClickSelectors([]string{"a"})
	// Crawljax: builder.crawlRules().followExternalLinks(true)
	extractor.SetFollowExternalLinks(true)

	ctx := context.Background()
	actions, err := extractor.Extract(ctx, page)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Crawljax parity: assertThat(extract, hasSize(3))
	if len(actions) != NUMBER_OF_CANDIDATES {
		t.Errorf("len(actions) = %d, want %d (Crawljax: hasSize)",
			len(actions), NUMBER_OF_CANDIDATES)
	}
}

// TestExtractIgnoreDownloadFiles tests that download links are excluded.
// Crawljax parity: CandidateElementExtractorTest.testExtractShouldIgnoreDownloadFiles()
// Expected: NUMBER_OF_CANDIDATES = 12
func TestExtractIgnoreDownloadFiles(t *testing.T) {
	const (
		// Crawljax exact value from CandidateElementExtractorTest.java
		// assertEquals(12, candidates.size())
		NUMBER_OF_CANDIDATES = 12
	)

	// Create test HTML with download links
	htmlContent := `<!DOCTYPE html>
<html>
<body>
<!-- Regular links (should be included) -->
<a href="/page1">Page 1</a>
<a href="/page2">Page 2</a>
<a href="/page3">Page 3</a>
<a href="/page4">Page 4</a>
<a href="/page5">Page 5</a>
<a href="/page6">Page 6</a>
<a href="/page7">Page 7</a>
<a href="/page8">Page 8</a>
<a href="/page9">Page 9</a>
<a href="/page10">Page 10</a>
<a href="/page11">Page 11</a>
<a href="/page12">Page 12</a>
<!-- Download links (should be excluded) -->
<a href="/file.pdf">PDF Download</a>
<a href="/file.ps">PS Download</a>
<a href="/file.zip">ZIP Download</a>
<a href="/file.mp3">MP3 Download</a>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlContent))
	}))
	defer server.Close()

	b := setupTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	cfg, _ := config.New(server.URL)
	extractor := NewCandidateElementExtractor(cfg)
	extractor.SetClickSelectors([]string{"a"})

	ctx := context.Background()
	actions, err := extractor.Extract(ctx, page)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Crawljax parity: assertEquals(12, candidates.size())
	if len(actions) != NUMBER_OF_CANDIDATES {
		t.Errorf("len(actions) = %d, want %d (Crawljax: assertEquals)",
			len(actions), NUMBER_OF_CANDIDATES)
	}
}

// TestExtractElementAddition tests single element addition.
// Crawljax parity: CandidateElementExtractorTest.testElementAddition()
// Expected: NUMBER_OF_RESULTS = 1
func TestExtractElementAddition(t *testing.T) {
	const (
		// Crawljax exact value from CandidateElementExtractorTest.java
		// Assert.assertEquals(1, results.size())
		NUMBER_OF_RESULTS = 1
	)

	// Create test HTML with single link
	htmlContent := `<!DOCTYPE html>
<html>
<body>
<a>Single Link</a>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlContent))
	}))
	defer server.Close()

	b := setupTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	cfg, _ := config.New(server.URL)
	extractor := NewCandidateElementExtractor(cfg)
	extractor.SetClickSelectors([]string{"a"})

	ctx := context.Background()
	actions, err := extractor.Extract(ctx, page)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Crawljax parity: Assert.assertEquals(1, results.size())
	if len(actions) != NUMBER_OF_RESULTS {
		t.Errorf("len(actions) = %d, want %d (Crawljax: assertEquals)",
			len(actions), NUMBER_OF_RESULTS)
	}
}
