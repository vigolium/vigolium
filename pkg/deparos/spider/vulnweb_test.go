package spider

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"testing"

	"golang.org/x/net/html"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVulnWebModRewriteShopExtraction tests link extraction from testphp.vulnweb.com/Mod_Rewrite_Shop/
// Sample HTML from: curl -s 'http://testphp.vulnweb.com/Mod_Rewrite_Shop/' | head -100
func TestVulnWebModRewriteShopExtraction(t *testing.T) {
	// Actual HTML from testphp.vulnweb.com/Mod_Rewrite_Shop/
	htmlContent := `<html>
<div id="content">
        <div class='product'><table><tr><td width='180px'><img src='images/1.jpg'></td><td width='400px'><a href='Details/network-attached-storage-dlink/1/'>Network Storage D-Link DNS-313 enclosure 1 x SATA</a></td><td width='50px' bgcolor='#F8F8F8'><a href='Details/network-attached-storage-dlink/1/'>Price<br>359 &euro;</a></td></table></tr></div><div class='product'><table><tr><td width='180px'><img src='images/2.jpg'></td><td width='400px'><a href='Details/web-camera-a4tech/2/'>Web Camera A4Tech PK-335E</a></td><td width='50px' bgcolor='#F8F8F8'><a href='Details/web-camera-a4tech/2/'>Price<br>10 &euro;</a></td></table></tr></div><div class='product'><table><tr><td width='180px'><img src='images/3.jpg'></td><td width='400px'><a href='Details/color-printer/3/'>Laser Color Printer HP LaserJet M551dn, A4</a></td><td width='50px' bgcolor='#F8F8F8'><a href='Details/color-printer/3/'>Price<br>812 &euro;</a></td></table></tr></div></div>
</html>`

	baseURL, err := url.Parse("http://testphp.vulnweb.com/Mod_Rewrite_Shop/")
	require.NoError(t, err)

	// Create the full extraction coordinator to test all extractors
	resolver := NewURLResolver()
	factory := NewExtractorFactory(resolver)
	coordinator := factory.CreateCoordinator()

	// Create response
	response := NewHTTPResponse(baseURL, nil, []byte(htmlContent), 0)
	err = response.ParseHTML()
	require.NoError(t, err)

	// Extract using the coordinator's internal method
	result, err := coordinator.extractInternal(context.Background(), baseURL, response)
	require.NoError(t, err)

	// Print all discovered links for debugging
	fmt.Println("=== Discovered Links ===")
	for i, link := range result.Links {
		fmt.Printf("%d: %s\n", i+1, link.String())
	}
	fmt.Println()
	fmt.Println("=== JS Links ===")
	for i, link := range result.JSURLs {
		fmt.Printf("%d: %s\n", i+1, link.String())
	}
	fmt.Println()

	// Expected URLs that should be extracted
	expectedURLs := map[string]bool{
		// Image sources (relative paths)
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/images/1.jpg": true,
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/images/2.jpg": true,
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/images/3.jpg": true,

		// Anchor hrefs (relative paths) - note each product has 2 links to the same URL
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/": true,
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/web-camera-a4tech/2/":              true,
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/color-printer/3/":                  true,
	}

	// Collect actual URLs
	actualURLs := make(map[string]bool)
	for _, link := range result.Links {
		actualURLs[link.String()] = true
	}

	fmt.Println("=== Expected URLs ===")
	for u := range expectedURLs {
		fmt.Printf("  %s\n", u)
	}

	fmt.Println("\n=== Actual URLs ===")
	for u := range actualURLs {
		fmt.Printf("  %s\n", u)
	}

	// Verify all expected URLs are found
	for expectedURL := range expectedURLs {
		assert.True(t, actualURLs[expectedURL], "Expected URL not found: %s", expectedURL)
	}

	// Should find at least 6 unique URLs (3 images + 3 product detail pages)
	// Note: there are 6 <a> tags but they link to 3 unique URLs (each product has 2 identical links)
	assert.GreaterOrEqual(t, len(actualURLs), 6, "Should find at least 6 unique URLs")
}

// TestHTMLAttributeExtractor_RelativePaths tests that relative paths are correctly resolved
func TestHTMLAttributeExtractor_RelativePaths(t *testing.T) {
	resolver := NewURLResolver()
	extractor := NewHTMLAttributeExtractor(resolver)

	tests := []struct {
		name         string
		baseURL      string
		htmlContent  string
		expectedURLs []string
	}{
		{
			name:    "Relative path without leading slash",
			baseURL: "http://example.com/shop/",
			htmlContent: `<html><body>
				<img src='images/photo.jpg'>
				<a href='Details/product/1/'>Product</a>
			</body></html>`,
			expectedURLs: []string{
				"http://example.com/shop/images/photo.jpg",
				"http://example.com/shop/Details/product/1/",
			},
		},
		{
			name:    "Relative path with leading slash",
			baseURL: "http://example.com/shop/",
			htmlContent: `<html><body>
				<img src='/images/photo.jpg'>
				<a href='/Details/product/1/'>Product</a>
			</body></html>`,
			expectedURLs: []string{
				"http://example.com/images/photo.jpg",
				"http://example.com/Details/product/1/",
			},
		},
		{
			name:    "Mixed relative paths",
			baseURL: "http://example.com/shop/category/",
			htmlContent: `<html><body>
				<img src='../images/photo.jpg'>
				<a href='./product/'>Product</a>
				<a href='item'>Item</a>
			</body></html>`,
			expectedURLs: []string{
				"http://example.com/shop/images/photo.jpg",
				"http://example.com/shop/category/product/",
				"http://example.com/shop/category/item",
			},
		},
		{
			name:    "VulnWeb style paths",
			baseURL: "http://testphp.vulnweb.com/Mod_Rewrite_Shop/",
			htmlContent: `<html><body>
				<img src='images/1.jpg'>
				<a href='Details/network-attached-storage-dlink/1/'>Product</a>
			</body></html>`,
			expectedURLs: []string{
				"http://testphp.vulnweb.com/Mod_Rewrite_Shop/images/1.jpg",
				"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, err := url.Parse(tt.baseURL)
			require.NoError(t, err)

			doc, err := html.Parse(bytes.NewReader([]byte(tt.htmlContent)))
			require.NoError(t, err)

			response := &HTTPResponse{
				URL:  baseURL,
				HTML: doc,
				Body: []byte(tt.htmlContent),
			}

			discovered := []*DiscoveredLink{}
			callback := func(link *DiscoveredLink) {
				discovered = append(discovered, link)
			}

			err = extractor.Extract(context.Background(), baseURL, response, callback)
			require.NoError(t, err)

			// Collect actual URLs
			actualURLs := make(map[string]bool)
			for _, link := range discovered {
				actualURLs[link.URL.String()] = true
			}

			// Verify expected URLs
			for _, expectedURL := range tt.expectedURLs {
				assert.True(t, actualURLs[expectedURL], "Expected URL not found: %s\nActual URLs: %v", expectedURL, actualURLs)
			}
		})
	}
}

// TestFullCoordinatorExtraction tests the full coordinator with vulnweb-like content
func TestFullCoordinatorExtraction(t *testing.T) {
	// More complete HTML with various link types
	htmlContent := `<!DOCTYPE html>
<html>
<head>
    <title>Shop</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="js/app.js"></script>
</head>
<body>
    <header>
        <nav>
            <a href="/">Home</a>
            <a href="/products/">Products</a>
            <a href="/about/">About</a>
        </nav>
    </header>
    <main>
        <div class='product'>
            <img src='images/1.jpg'>
            <a href='Details/product-1/1/'>Product 1</a>
        </div>
        <div class='product'>
            <img src='images/2.jpg'>
            <a href='Details/product-2/2/'>Product 2</a>
        </div>
    </main>
    <footer>
        <a href="/privacy/">Privacy Policy</a>
    </footer>
</body>
</html>`

	baseURL, err := url.Parse("http://testphp.vulnweb.com/Mod_Rewrite_Shop/")
	require.NoError(t, err)

	resolver := NewURLResolver()
	factory := NewExtractorFactory(resolver)
	coordinator := factory.CreateCoordinator()

	response := NewHTTPResponse(baseURL, nil, []byte(htmlContent), 0)
	err = response.ParseHTML()
	require.NoError(t, err)

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)
	require.NoError(t, err)

	// Print results
	fmt.Println("=== Full Coordinator Test ===")
	fmt.Printf("Total links found: %d\n", len(result.Links))
	fmt.Printf("JS links found: %d\n", len(result.JSURLs))

	// Collect unique URLs
	uniqueURLs := make(map[string]bool)
	for _, link := range result.Links {
		uniqueURLs[link.String()] = true
	}

	fmt.Println("\n=== Unique URLs ===")
	for u := range uniqueURLs {
		fmt.Printf("  %s\n", u)
	}

	// Expected URLs
	expectedURLs := []string{
		// CSS and JS
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/css/style.css",
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/js/app.js",
		// Navigation links (absolute paths)
		"http://testphp.vulnweb.com/",
		"http://testphp.vulnweb.com/products/",
		"http://testphp.vulnweb.com/about/",
		// Product images (relative paths)
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/images/1.jpg",
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/images/2.jpg",
		// Product detail links (relative paths)
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/product-1/1/",
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/product-2/2/",
		// Footer link (absolute path)
		"http://testphp.vulnweb.com/privacy/",
	}

	for _, expectedURL := range expectedURLs {
		assert.True(t, uniqueURLs[expectedURL], "Expected URL not found: %s", expectedURL)
	}

	// Verify JS link is found (may be found by multiple extractors)
	assert.GreaterOrEqual(t, len(result.JSURLs), 1, "Should find at least 1 JS link")
	jsURLSet := make(map[string]bool)
	for _, link := range result.JSURLs {
		jsURLSet[link.String()] = true
	}
	assert.True(t, jsURLSet["http://testphp.vulnweb.com/Mod_Rewrite_Shop/js/app.js"], "JS file should be found")
}
