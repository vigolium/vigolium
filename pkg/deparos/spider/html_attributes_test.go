package spider

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTMLAttributeExtractor_Extract(t *testing.T) {
	resolver := NewURLResolver()

	extractor := NewHTMLAttributeExtractor(resolver)

	tests := []struct {
		name          string
		baseURL       string
		htmlContent   string
		expectedCount int
		expectedURLs  []string
		expectedTypes []ResourceType
		expectedElems []string
		expectedAttrs []string
	}{
		{
			name:    "a tag with href",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<a href="/page1">Link 1</a>
					<a href="https://example.com/page2">Link 2</a>
				</body>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/page1", "https://example.com/page2"},
			expectedTypes: []ResourceType{ResourceHTML, ResourceHTML},
			expectedElems: []string{"a", "a"},
			expectedAttrs: []string{"href", "href"},
		},
		{
			name:    "img tag with src and srcset",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<img src="/images/photo.jpg" alt="Photo">
					<img srcset="/images/small.png 480w, /images/large.png 800w">
				</body>
			</html>`,
			expectedCount: 3,
			expectedURLs:  []string{"https://example.com/images/photo.jpg", "https://example.com/images/small.png", "https://example.com/images/large.png"},
			expectedTypes: []ResourceType{ResourceJPEG, ResourcePNG, ResourcePNG},
		},
		{
			name:    "script tag with src",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<head>
					<script src="/js/app.js"></script>
					<script src="https://example.com/js/lib.js"></script>
				</head>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/js/app.js", "https://example.com/js/lib.js"},
			expectedTypes: []ResourceType{ResourceScript, ResourceScript},
			expectedElems: []string{"script", "script"},
			expectedAttrs: []string{"src", "src"},
		},
		{
			name:    "link tag with href - CSS",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<head>
					<link rel="stylesheet" href="/css/style.css" type="text/css">
					<link rel="icon" href="/favicon.ico">
				</head>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/css/style.css", "https://example.com/favicon.ico"},
			expectedTypes: []ResourceType{ResourceHTML, ResourceHTML},
		},
		{
			name:    "base href overrides baseURL",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<head>
					<base href="https://example.com/subdir/">
				</head>
				<body>
					<a href="page1">Link</a>
					<img src="image.jpg">
				</body>
			</html>`,
			expectedCount: 3, // base href + a href + img src
			expectedURLs:  []string{"https://example.com/subdir/", "https://example.com/subdir/page1", "https://example.com/subdir/image.jpg"},
			expectedTypes: []ResourceType{ResourceHTML, ResourceHTML, ResourceJPEG},
		},
		{
			name:    "iframe",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<iframe src="/iframe.html"></iframe>
				</body>
			</html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/iframe.html"},
			expectedTypes: []ResourceType{ResourceHTML},
		},
		{
			name:    "frame in frameset",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<frameset>
					<frame src="/frame1.html">
					<frame src="/frame2.html">
				</frameset>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/frame1.html", "https://example.com/frame2.html"},
			expectedTypes: []ResourceType{ResourceHTML, ResourceHTML},
		},
		{
			name:    "video and audio tags",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<video src="/video.mp4"></video>
					<bgsound src="/sound.wav"></bgsound>
					<sound src="/audio.mp3"></sound>
				</body>
			</html>`,
			expectedCount: 3,
			expectedURLs:  []string{"https://example.com/video.mp4", "https://example.com/sound.wav", "https://example.com/audio.mp3"},
			expectedTypes: []ResourceType{ResourceVideo, ResourceAudio, ResourceAudio},
		},
		{
			name:    "embed and object tags",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<embed src="/plugin.swf"></embed>
					<object data="/content.pdf" codebase="/base/"></object>
				</body>
			</html>`,
			expectedCount: 3,
			// Note: order depends on extractFromElement implementation
			// object extracts: code (not present), codebase, data
			expectedURLs:  []string{"https://example.com/plugin.swf", "https://example.com/base/", "https://example.com/content.pdf"},
			expectedTypes: []ResourceType{ResourceBinary, ResourceHTML, ResourceBinary},
		},
		{
			name:    "applet tag",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<applet code="MyApplet.class" codebase="/applets/" archive="lib.jar"></applet>
				</body>
			</html>`,
			expectedCount: 3,
			// Note: code and archive are resolved relative to base URL, not codebase
			// codebase is extracted separately as its own link
			expectedURLs:  []string{"https://example.com/MyApplet.class", "https://example.com/applets/", "https://example.com/lib.jar"},
			expectedTypes: []ResourceType{ResourceBinary, ResourceHTML, ResourceBinary},
		},
		{
			name:    "body background",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body background="/bg.gif">
					<table background="/table-bg.png">
						<tr>
							<td background="/cell-bg.jpg"></td>
						</tr>
					</table>
				</body>
			</html>`,
			expectedCount: 3,
			expectedURLs:  []string{"https://example.com/bg.gif", "https://example.com/table-bg.png", "https://example.com/cell-bg.jpg"},
			expectedTypes: []ResourceType{ResourceGIF, ResourcePNG, ResourceJPEG},
		},
		{
			name:    "blockquote, ins, del cite attributes",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<blockquote cite="/quote.html">Quote</blockquote>
					<ins cite="/insert.html">Inserted</ins>
					<del cite="/delete.html">Deleted</del>
				</body>
			</html>`,
			expectedCount: 3,
			expectedURLs:  []string{"https://example.com/quote.html", "https://example.com/insert.html", "https://example.com/delete.html"},
			expectedTypes: []ResourceType{ResourceHTML, ResourceHTML, ResourceHTML},
		},
		{
			name:    "input type=image",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<input type="image" src="/button.png">
					<input type="submit" src="/submit.png">
				</body>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/button.png", "https://example.com/submit.png"},
			expectedTypes: []ResourceType{ResourcePNG, ResourceBinary},
		},
		{
			name:    "SVG elements",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<svg>
						<image xlink:href="/image.svg"></image>
						<feimage xlink:href="/filter.svg"></feimage>
					</svg>
				</body>
			</html>`,
			expectedCount: 3,
			// image tag extracts src, href, and xlink:href
			// In this case, only xlink:href is present, but HTML parser may also add regular href
			expectedURLs: []string{"https://example.com/image.svg", "https://example.com/image.svg", "https://example.com/filter.svg"},
		},
		{
			name:    "meta url attribute",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<head>
					<meta url="/meta-target.html">
				</head>
			</html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/meta-target.html"},
			expectedTypes: []ResourceType{ResourceHTML},
		},
		{
			name:    "html manifest",
			baseURL: "https://example.com/",
			htmlContent: `<html manifest="/app.manifest">
			</html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/app.manifest"},
			expectedTypes: []ResourceType{ResourceBinary},
		},
		{
			name:    "source tag",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<video>
						<source src="/video.mp4">
						<source src="/video.webm">
					</video>
				</body>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/video.mp4", "https://example.com/video.webm"},
			expectedTypes: []ResourceType{ResourceBinary, ResourceBinary},
		},
		{
			name:    "URL validation - dot paths filtered",
			baseURL: "https://example.com/page",
			htmlContent: `<html>
				<body>
					<a href=".">Current</a>
					<a href="..">Parent</a>
					<a href="/valid">Valid</a>
				</body>
			</html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/valid"},
		},
		{
			name:    "URL validation - invalid protocols filtered",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<a href="javascript:alert(1)">JS</a>
					<a href="data:text/html,<h1>Data</h1>">Data</a>
					<a href="mailto:test@example.com">Email</a>
					<a href="/valid">Valid</a>
				</body>
			</html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/valid"},
		},
		{
			name:    "URL normalization - space encoding",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<a href="/path with spaces">Spaces</a>
				</body>
			</html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/path%20with%20spaces"},
		},
		{
			// Note: HTMLAttributeExtractor no longer checks scope - caller handles scope filtering
			name:    "Multiple domains - all extracted",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<a href="https://other.com/page">Other domain</a>
					<a href="https://example.com/page">Same domain</a>
				</body>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://other.com/page", "https://example.com/page"},
		},
		{
			name:    "Subdomain in scope",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<a href="https://api.example.com/resource">API subdomain</a>
					<a href="https://cdn.example.com/asset.js">CDN subdomain</a>
				</body>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://api.example.com/resource", "https://cdn.example.com/asset.js"},
		},
		{
			name:    "Empty attributes ignored",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<a href="">Empty</a>
					<img src="">
					<a href="/valid">Valid</a>
				</body>
			</html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/valid"},
		},
		{
			name:    "Same as base URL filtered",
			baseURL: "https://example.com/page",
			htmlContent: `<html>
				<body>
					<a href="https://example.com/page">Same</a>
					<a href="/other">Different</a>
				</body>
			</html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/other"},
		},
		{
			name:    "Image extension detection",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<img src="/photo.jpg">
					<img src="/photo.jpeg">
					<img src="/icon.gif">
					<img src="/logo.png">
					<img src="/texture.bmp">
					<img src="/scan.tif">
					<img src="/scan2.tiff">
					<img src="/unknown.webp">
				</body>
			</html>`,
			expectedCount: 8,
			expectedTypes: []ResourceType{
				ResourceJPEG,
				ResourceJPEG,
				ResourceGIF,
				ResourcePNG,
				ResourceBMP,
				ResourceTIFF,
				ResourceTIFF,
				ResourceImage, // Unknown extension
			},
		},
		{
			name:    "Link type determination",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<head>
					<link href="/style.css" type="text/css">
					<link href="/script.js" type="text/javascript">
					<link href="/icon.png" type="image/png">
					<link href="/other" type="application/json">
				</head>
			</html>`,
			expectedCount: 4,
			expectedURLs: []string{
				"https://example.com/style.css",
				"https://example.com/script.js",
				"https://example.com/icon.png",
				"https://example.com/other",
			},
			expectedTypes: []ResourceType{
				ResourceHTML,   // CSS
				ResourceScript, // JavaScript
				ResourcePNG,    // Image - detectImageType returns ResourcePNG for .png
				ResourceHTML,   // Default
			},
		},
		{
			name:    "Nested elements",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<div>
						<ul>
							<li><a href="/item1">Item 1</a></li>
							<li><a href="/item2">Item 2</a></li>
						</ul>
					</div>
				</body>
			</html>`,
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/item1", "https://example.com/item2"},
		},
		{
			name:    "Multiple attributes on same tag",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<body>
					<object code="/applet.class" codebase="/base/" data="/data.bin"></object>
				</body>
			</html>`,
			expectedCount: 3,
			// code, codebase, data are extracted separately (not resolved relative to codebase)
			expectedURLs: []string{"https://example.com/applet.class", "https://example.com/base/", "https://example.com/data.bin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, err := url.Parse(tt.baseURL)
			require.NoError(t, err)

			// Parse HTML
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

			// Exact count validation
			require.Len(t, discovered, tt.expectedCount, "Unexpected number of discovered links")

			// Set-based URL comparison to handle map iteration randomness
			if tt.expectedURLs != nil {
				expectedURLSet := make(map[string]bool)
				for _, u := range tt.expectedURLs {
					expectedURLSet[u] = true
				}

				actualURLSet := make(map[string]bool)
				for _, link := range discovered {
					actualURLSet[link.URL.String()] = true
				}

				assert.Equal(t, expectedURLSet, actualURLSet, "URL set mismatch")
			}

			// Validate resource types
			if tt.expectedTypes != nil {
				actualTypes := make(map[ResourceType]int)
				for _, link := range discovered {
					actualTypes[link.ResourceType]++
				}

				expectedTypes := make(map[ResourceType]int)
				for _, rt := range tt.expectedTypes {
					expectedTypes[rt]++
				}

				assert.Equal(t, expectedTypes, actualTypes, "Resource type distribution mismatch")
			}

			// Validate elements
			if tt.expectedElems != nil {
				actualElems := make(map[string]int)
				for _, link := range discovered {
					actualElems[link.Element]++
				}

				expectedElems := make(map[string]int)
				for _, elem := range tt.expectedElems {
					expectedElems[elem]++
				}

				assert.Equal(t, expectedElems, actualElems, "Element distribution mismatch")
			}

			// Validate attributes
			if tt.expectedAttrs != nil {
				actualAttrs := make(map[string]int)
				for _, link := range discovered {
					actualAttrs[link.Attribute]++
				}

				expectedAttrs := make(map[string]int)
				for _, attr := range tt.expectedAttrs {
					expectedAttrs[attr]++
				}

				assert.Equal(t, expectedAttrs, actualAttrs, "Attribute distribution mismatch")
			}

			// Verify all discovered links have correct source type
			for i, link := range discovered {
				assert.Equal(t, SourceHTMLAttribute, link.SourceType, "Source type mismatch at index %d", i)
			}
		})
	}
}

func TestHTMLAttributeExtractor_NilHTML(t *testing.T) {
	resolver := NewURLResolver()
	extractor := NewHTMLAttributeExtractor(resolver)

	baseURL, _ := url.Parse("https://example.com")
	response := &HTTPResponse{
		URL:  baseURL,
		HTML: nil, // No HTML parsed
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := extractor.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)
	require.Len(t, discovered, 0)
}

func TestHTMLAttributeExtractor_SrcsetParsing(t *testing.T) {
	resolver := NewURLResolver()
	extractor := NewHTMLAttributeExtractor(resolver)

	tests := []struct {
		name          string
		srcset        string
		expectedCount int
		expectedURLs  []string
	}{
		{
			name:          "Single URL with width descriptor",
			srcset:        "/image.jpg 800w",
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/image.jpg"},
		},
		{
			name:          "Multiple URLs with width descriptors",
			srcset:        "/small.jpg 480w, /medium.jpg 800w, /large.jpg 1200w",
			expectedCount: 3,
			expectedURLs:  []string{"https://example.com/small.jpg", "https://example.com/medium.jpg", "https://example.com/large.jpg"},
		},
		{
			name:          "Multiple URLs with pixel density descriptors",
			srcset:        "/1x.jpg 1x, /2x.jpg 2x",
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/1x.jpg", "https://example.com/2x.jpg"},
		},
		{
			name:          "URLs without descriptors",
			srcset:        "/image1.jpg, /image2.jpg",
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/image1.jpg", "https://example.com/image2.jpg"},
		},
		{
			name:          "URLs with extra whitespace",
			srcset:        "  /image1.jpg  1x  ,   /image2.jpg   2x  ",
			expectedCount: 2,
			expectedURLs:  []string{"https://example.com/image1.jpg", "https://example.com/image2.jpg"},
		},
		{
			name:          "Empty srcset",
			srcset:        "",
			expectedCount: 0,
		},
		{
			name:          "Only commas",
			srcset:        ",,,",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, _ := url.Parse("https://example.com/")

			htmlContent := `<html><body><img srcset="` + tt.srcset + `"></body></html>`

			doc, err := html.Parse(bytes.NewReader([]byte(htmlContent)))
			require.NoError(t, err)

			response := &HTTPResponse{
				URL:  baseURL,
				HTML: doc,
				Body: []byte(htmlContent),
			}

			discovered := []*DiscoveredLink{}
			callback := func(link *DiscoveredLink) {
				discovered = append(discovered, link)
			}

			err = extractor.Extract(context.Background(), baseURL, response, callback)
			require.NoError(t, err)

			require.Len(t, discovered, tt.expectedCount)

			// Set-based comparison
			if len(tt.expectedURLs) > 0 {
				expectedURLSet := make(map[string]bool)
				for _, u := range tt.expectedURLs {
					expectedURLSet[u] = true
				}

				actualURLSet := make(map[string]bool)
				for _, link := range discovered {
					actualURLSet[link.URL.String()] = true
				}

				assert.Equal(t, expectedURLSet, actualURLSet)
			}
		})
	}
}

func TestHTMLAttributeExtractor_BaseHrefOverride(t *testing.T) {
	resolver := NewURLResolver()
	extractor := NewHTMLAttributeExtractor(resolver)

	tests := []struct {
		name         string
		baseURL      string
		htmlContent  string
		expectedURLs []string
	}{
		{
			name:    "Base href with trailing slash",
			baseURL: "https://example.com/page",
			htmlContent: `<html>
				<head>
					<base href="https://example.com/subdir/">
				</head>
				<body>
					<a href="page1">Link</a>
					<img src="image.jpg">
				</body>
			</html>`,
			expectedURLs: []string{
				"https://example.com/subdir/",
				"https://example.com/subdir/page1",
				"https://example.com/subdir/image.jpg",
			},
		},
		{
			name:    "Base href without trailing slash",
			baseURL: "https://example.com/page",
			htmlContent: `<html>
				<head>
					<base href="https://example.com/subdir">
				</head>
				<body>
					<a href="page1">Link</a>
				</body>
			</html>`,
			expectedURLs: []string{
				"https://example.com/subdir",
				"https://example.com/page1",
			},
		},
		{
			name:    "Multiple base tags - only first is used",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<head>
					<base href="https://example.com/base1/">
					<base href="https://example.com/base2/">
				</head>
				<body>
					<a href="page">Link</a>
				</body>
			</html>`,
			expectedURLs: []string{
				"https://example.com/base1/",
				"https://example.com/base2/",     // Both base tags are extracted
				"https://example.com/base1/page", // But only first affects resolution
			},
		},
		{
			name:    "Base href with different domain",
			baseURL: "https://example.com/",
			htmlContent: `<html>
				<head>
					<base href="https://cdn.example.com/assets/">
				</head>
				<body>
					<img src="logo.png">
				</body>
			</html>`,
			expectedURLs: []string{
				"https://cdn.example.com/assets/",
				"https://cdn.example.com/assets/logo.png",
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

			require.Len(t, discovered, len(tt.expectedURLs), "URL count mismatch")

			// Set-based comparison
			expectedURLSet := make(map[string]bool)
			for _, u := range tt.expectedURLs {
				expectedURLSet[u] = true
			}

			actualURLSet := make(map[string]bool)
			for _, link := range discovered {
				actualURLSet[link.URL.String()] = true
			}

			assert.Equal(t, expectedURLSet, actualURLSet)
		})
	}
}

func TestHTMLAttributeExtractor_AllTags(t *testing.T) {
	// Test that all 32 tags are supported
	resolver := NewURLResolver()
	extractor := NewHTMLAttributeExtractor(resolver)

	htmlContent := `<html manifest="/html-manifest">
		<head>
			<base href="/base/">
			<link href="/link">
			<meta url="/meta">
			<script src="/script"></script>
		</head>
		<body background="/body-bg">
			<a href="/a">Link</a>
			<img src="/img">
			<applet code="/applet"></applet>
			<area href="/area">
			<bgsound src="/bgsound">
			<sound src="/sound">
			<embed src="/embed">
			<fig src="/fig">
			<iframe src="/iframe"></iframe>
			<li src="/li">
			<note src="/note">
			<object data="/object"></object>
			<ul src="/ul">
			<blockquote cite="/blockquote">
			<ins cite="/ins">
			<del cite="/del">
			<video src="/video"></video>
			<svg src="/svg"></svg>
			<svg>
				<image xlink:href="/image"></image>
				<feimage xlink:href="/feimage"></feimage>
			</svg>
			<isindex src="/isindex">
			<source src="/source">
			<table background="/table">
				<tr><td background="/td"></td></tr>
			</table>
			<input type="image" src="/input">
		</body>
	</html>`

	baseURL, _ := url.Parse("https://example.com/")
	doc, err := html.Parse(bytes.NewReader([]byte(htmlContent)))
	require.NoError(t, err)

	response := &HTTPResponse{
		URL:  baseURL,
		HTML: doc,
		Body: []byte(htmlContent),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err = extractor.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	// Exact count validation - should extract from all tags
	// Note: image element extracts from both href and xlink:href, resulting in duplicate /image URL
	require.Len(t, discovered, 32, "Should extract from all 32 tags")

	// Verify critical URLs are present
	criticalURLs := map[string]bool{
		"https://example.com/html-manifest": true,
		"https://example.com/base/":         true,
		"https://example.com/link":          true,
		"https://example.com/meta":          true,
		"https://example.com/script":        true,
		"https://example.com/body-bg":       true,
		"https://example.com/a":             true,
		"https://example.com/img":           true,
		"https://example.com/applet":        true,
		"https://example.com/area":          true,
		"https://example.com/bgsound":       true,
		"https://example.com/sound":         true,
		"https://example.com/embed":         true,
		"https://example.com/fig":           true,
		"https://example.com/iframe":        true,
		"https://example.com/li":            true,
		"https://example.com/note":          true,
		"https://example.com/object":        true,
		"https://example.com/ul":            true,
		"https://example.com/blockquote":    true,
		"https://example.com/ins":           true,
		"https://example.com/del":           true,
		"https://example.com/video":         true,
		"https://example.com/svg":           true,
		"https://example.com/image":         true,
		"https://example.com/feimage":       true,
		"https://example.com/isindex":       true,
		"https://example.com/source":        true,
		"https://example.com/table":         true,
		"https://example.com/td":            true,
		"https://example.com/input":         true,
	}

	actualURLSet := make(map[string]bool)
	for _, link := range discovered {
		actualURLSet[link.URL.String()] = true
	}

	// Verify all critical URLs are found
	for criticalURL := range criticalURLs {
		assert.True(t, actualURLSet[criticalURL], "Expected to find critical URL: %s", criticalURL)
	}

	// Verify specific elements were found
	foundElements := make(map[string]bool)
	for _, link := range discovered {
		foundElements[link.Element] = true
	}

	expectedElements := []string{
		"a", "img", "script", "link", "applet", "area", "base",
		"bgsound", "sound", "body", "embed", "fig",
		"iframe", "li", "meta", "note", "object", "ul",
		"blockquote", "ins", "del", "video", "image", "svg",
		"isindex", "source", "table", "td", "input", "feImage", "html",
	}

	for _, elem := range expectedElements {
		assert.True(t, foundElements[elem], "Expected to find element: %s", elem)
	}

	// Verify all links have correct source type
	for _, link := range discovered {
		assert.Equal(t, SourceHTMLAttribute, link.SourceType)
	}

	// Verify resource types are set correctly for known types
	resourceTypeCounts := make(map[ResourceType]int)
	for _, link := range discovered {
		resourceTypeCounts[link.ResourceType]++
	}

	// At minimum, we should have HTML and binary resources
	assert.Greater(t, resourceTypeCounts[ResourceHTML], 0, "Should have HTML resources")
	assert.Greater(t, resourceTypeCounts[ResourceBinary], 0, "Should have binary resources")
}

func TestHTMLAttributeExtractor_ModernJSPatterns(t *testing.T) {
	// Test modern JavaScript loading patterns used by modern web apps
	resolver := NewURLResolver()
	extractor := NewHTMLAttributeExtractor(resolver)

	tests := []struct {
		name          string
		htmlContent   string
		expectedCount int
		expectedURLs  []string
		expectedTypes []ResourceType
		expectedJSCnt int // Number of ResourceScript links (for JS URL extraction)
	}{
		{
			name: "link rel=preload as=script",
			htmlContent: `<html><head>
				<link rel="preload" as="script" href="/app.js">
			</head></html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/app.js"},
			expectedTypes: []ResourceType{ResourceScript},
			expectedJSCnt: 1,
		},
		{
			name: "link rel=modulepreload",
			htmlContent: `<html><head>
				<link rel="modulepreload" href="/module.mjs">
			</head></html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/module.mjs"},
			expectedTypes: []ResourceType{ResourceScript},
			expectedJSCnt: 1,
		},
		{
			name: "link rel=prefetch as=script",
			htmlContent: `<html><head>
				<link rel="prefetch" as="script" href="/lazy.js">
			</head></html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/lazy.js"},
			expectedTypes: []ResourceType{ResourceScript},
			expectedJSCnt: 1,
		},
		{
			name: "script type=module",
			htmlContent: `<html><head>
				<script type="module" src="/esm/app.mjs"></script>
			</head></html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/esm/app.mjs"},
			expectedTypes: []ResourceType{ResourceScript},
			expectedJSCnt: 1,
		},
		{
			name: "mixed modern JS patterns",
			htmlContent: `<html><head>
				<link rel="preload" as="script" href="/preload.js">
				<link rel="modulepreload" href="/module.mjs">
				<link rel="prefetch" as="script" href="/prefetch.js">
				<script type="module" src="/app.mjs"></script>
				<script src="/legacy.js"></script>
			</head></html>`,
			expectedCount: 5,
			expectedURLs: []string{
				"https://example.com/preload.js",
				"https://example.com/module.mjs",
				"https://example.com/prefetch.js",
				"https://example.com/app.mjs",
				"https://example.com/legacy.js",
			},
			expectedTypes: []ResourceType{
				ResourceScript,
				ResourceScript,
				ResourceScript,
				ResourceScript,
				ResourceScript,
			},
			expectedJSCnt: 5,
		},
		{
			name: "link rel=preload as=style (not script)",
			htmlContent: `<html><head>
				<link rel="preload" as="style" href="/styles.css">
			</head></html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/styles.css"},
			expectedTypes: []ResourceType{ResourceHTML}, // Not script
			expectedJSCnt: 0,                            // No JS
		},
		{
			name: "link as=script without preload/prefetch",
			htmlContent: `<html><head>
				<link as="script" href="/weird.js">
			</head></html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/weird.js"},
			expectedTypes: []ResourceType{ResourceScript},
			expectedJSCnt: 1,
		},
		{
			name: "link type=text/javascript (legacy)",
			htmlContent: `<html><head>
				<link type="text/javascript" href="/legacy-link.js">
			</head></html>`,
			expectedCount: 1,
			expectedURLs:  []string{"https://example.com/legacy-link.js"},
			expectedTypes: []ResourceType{ResourceScript},
			expectedJSCnt: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, _ := url.Parse("https://example.com/")

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

			// Validate count
			require.Len(t, discovered, tt.expectedCount, "Link count mismatch")

			// Validate JS count by checking ResourceType
			jsCount := 0
			for _, link := range discovered {
				if link.ResourceType == ResourceScript {
					jsCount++
				}
			}
			assert.Equal(t, tt.expectedJSCnt, jsCount, "JS resource count mismatch")

			// Validate URLs (set-based)
			if tt.expectedURLs != nil {
				expectedURLSet := make(map[string]bool)
				for _, u := range tt.expectedURLs {
					expectedURLSet[u] = true
				}

				actualURLSet := make(map[string]bool)
				for _, link := range discovered {
					actualURLSet[link.URL.String()] = true
				}

				assert.Equal(t, expectedURLSet, actualURLSet, "URL set mismatch")
			}

			// Validate resource types
			if tt.expectedTypes != nil {
				actualTypes := make(map[ResourceType]int)
				for _, link := range discovered {
					actualTypes[link.ResourceType]++
				}

				expectedTypes := make(map[ResourceType]int)
				for _, rt := range tt.expectedTypes {
					expectedTypes[rt]++
				}

				assert.Equal(t, expectedTypes, actualTypes, "Resource type distribution mismatch")
			}
		})
	}
}

func BenchmarkHTMLAttributeExtractor_Extract(b *testing.B) {
	resolver := NewURLResolver()
	extractor := NewHTMLAttributeExtractor(resolver)

	htmlContent := `<html>
		<head>
			<link rel="stylesheet" href="/css/style.css">
			<script src="/js/app.js"></script>
		</head>
		<body>
			<div class="header">
				<a href="/home">Home</a>
				<a href="/about">About</a>
				<a href="/contact">Contact</a>
			</div>
			<div class="content">
				<img src="/images/photo1.jpg">
				<img src="/images/photo2.jpg">
				<img src="/images/photo3.jpg">
				<p>Lorem ipsum dolor sit amet.</p>
			</div>
			<div class="footer">
				<a href="/privacy">Privacy</a>
				<a href="/terms">Terms</a>
			</div>
		</body>
	</html>`

	baseURL, _ := url.Parse("https://example.com/")
	doc, _ := html.Parse(bytes.NewReader([]byte(htmlContent)))

	response := &HTTPResponse{
		URL:  baseURL,
		HTML: doc,
		Body: []byte(htmlContent),
	}

	callback := func(link *DiscoveredLink) {
		// No-op
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.Extract(context.Background(), baseURL, response, callback)
	}
}

func BenchmarkHTMLAttributeExtractor_LargeHTML(b *testing.B) {
	resolver := NewURLResolver()
	extractor := NewHTMLAttributeExtractor(resolver)

	// Generate large HTML with many links
	var htmlBuilder strings.Builder
	htmlBuilder.WriteString("<html><body>")
	for i := 0; i < 100; i++ {
		htmlBuilder.WriteString(`<div>`)
		fmt.Fprintf(&htmlBuilder, `<a href="/link%d">Link</a>`, i)
		fmt.Fprintf(&htmlBuilder, `<img src="/image%d.jpg">`, i)
		fmt.Fprintf(&htmlBuilder, `<script src="/script%d.js"></script>`, i)
		htmlBuilder.WriteString(`</div>`)
	}
	htmlBuilder.WriteString("</body></html>")
	htmlContent := htmlBuilder.String()

	baseURL, _ := url.Parse("https://example.com/")
	doc, _ := html.Parse(bytes.NewReader([]byte(htmlContent)))

	response := &HTTPResponse{
		URL:  baseURL,
		HTML: doc,
		Body: []byte(htmlContent),
	}

	callback := func(link *DiscoveredLink) {
		// No-op
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.Extract(context.Background(), baseURL, response, callback)
	}
}
