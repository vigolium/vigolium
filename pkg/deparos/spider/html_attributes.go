package spider

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"
)

// HTMLAttributeExtractor extracts URLs from HTML tag attributes.
//
// Supported elements (32 tags from Burp Suite):
//   - a, img, script, link, applet, area, base, bgsound, sound, body
//   - embed, frame, fig, iframe, li, meta, note, object, ul, blockquote
//   - ins, del, video, image, svg, html, isindex, source, table, td
//   - input, feimage
//
// Note: This extractor does NOT check scope. Caller is responsible for scope filtering.
//
// Burp mapping: ap7.java (HTML attribute extractor)
type HTMLAttributeExtractor struct {
	urlResolver *URLResolver
}

// NewHTMLAttributeExtractor creates a new HTML attribute extractor.
func NewHTMLAttributeExtractor(urlResolver *URLResolver) *HTMLAttributeExtractor {
	return &HTMLAttributeExtractor{
		urlResolver: urlResolver,
	}
}

// Extract examines HTML content and reports discovered URLs from tag attributes.
//
// The extraction process:
//  1. Parse HTML DOM tree (using cached result from response.HTML)
//  2. Traverse DOM recursively
//  3. Handle <base href> to override baseURL
//  4. Extract URLs from each supported tag/attribute combination
//  5. Resolve relative URLs and check scope
//  6. Report via callback
//
// Burp mapping: ap7.a(hik var0, List<ahe> var1, int var2, c5e var3) - Lines 15-500
func (e *HTMLAttributeExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Ensure HTML is parsed (cached with sync.Once)
	if response.HTML == nil {
		return nil // Not HTML or parse failed
	}

	doc := response.HTML

	// Track current base URL (can be overridden by <base href>)
	currentBase := baseURL
	baseOverridden := false

	// Traverse DOM recursively
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tagName := strings.ToLower(n.Data)

			// Handle <base href> tag specially - it overrides the base URL
			// Burp mapping: Lines 350-358
			if tagName == "base" && !baseOverridden {
				if newBase := e.extractFromElement(n, currentBase, "base", callback); newBase != nil {
					currentBase = newBase
					baseOverridden = true
				}
			} else {
				// Extract URLs from other tags
				e.extractFromElement(n, currentBase, tagName, callback)
			}
		}

		// Traverse children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return nil
}

// extractFromElement extracts URLs from a single HTML element based on its tag name.
// Returns the resolved URL for <base> tag, nil otherwise.
//
// Burp mapping: Lines 312-491 (switch statement for each tag)
func (e *HTMLAttributeExtractor) extractFromElement(n *html.Node, baseURL *url.URL, tagName string, callback LinkCallback) *url.URL {
	// Map tag names to their attributes and resource types
	// This follows the exact mapping from Burp's ap7.java switch statement
	switch tagName {
	case "a":
		// Burp: case 0, lines 313-317
		e.extractAttr(n, "href", ResourceHTML, baseURL, callback)

	case "img":
		// Burp: case 1, lines 318-323
		e.extractAttr(n, "src", ResourceImage, baseURL, callback)
		e.extractSrcset(n, "srcset", ResourceImage, baseURL, callback)

	case "script":
		// Burp: case 2, lines 324-329
		e.extractAttr(n, "src", ResourceScript, baseURL, callback)
		e.extractAttr(n, "xlink:href", ResourceScript, baseURL, callback)

	case "link":
		// Burp: case 3, lines 330-336
		// Determine resource type from type, rel, and as attributes
		// Modern apps use: <link rel="preload" as="script">, <link rel="modulepreload">
		resType := e.determineLinkResourceType(n)
		e.extractAttr(n, "href", resType, baseURL, callback)
		e.extractAttr(n, "src", resType, baseURL, callback)

	case "applet":
		// Burp: case 4, lines 337-344
		e.extractAttr(n, "code", ResourceBinary, baseURL, callback)
		e.extractAttr(n, "codebase", ResourceHTML, baseURL, callback)
		e.extractAttr(n, "archive", ResourceBinary, baseURL, callback)
		e.extractAttr(n, "object", ResourceBinary, baseURL, callback)

	case "area":
		// Burp: case 5, lines 345-349
		e.extractAttr(n, "href", ResourceHTML, baseURL, callback)

	case "base":
		// Burp: case 6, lines 350-359
		// Special handling: extract href and return it to override base URL
		value := getAttr(n, "href")
		if value == "" {
			return nil
		}
		resolved, err := e.resolveAndValidate(value, baseURL)
		if err != nil {
			return nil
		}
		// Report the link
		e.reportLink(n, "href", value, resolved, ResourceHTML, callback)
		return resolved // Return to override base URL

	case "bgsound":
		// Burp: case 7, lines 360-364
		e.extractAttr(n, "src", ResourceAudio, baseURL, callback)

	case "sound":
		// Burp: case 8, lines 365-369
		e.extractAttr(n, "src", ResourceAudio, baseURL, callback)

	case "body":
		// Burp: case 9, lines 370-375
		e.extractAttr(n, "background", ResourceImage, baseURL, callback)
		e.extractAttr(n, "location", ResourceHTML, baseURL, callback)

	case "embed":
		// Burp: case 10, lines 376-381
		e.extractAttr(n, "src", ResourceBinary, baseURL, callback)
		e.extractAttr(n, "code", ResourceBinary, baseURL, callback)

	case "frame":
		// Burp: case 11, lines 382-386
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "fig":
		// Burp: case 12, lines 387-391
		e.extractAttr(n, "src", ResourceImage, baseURL, callback)

	case "iframe":
		// Burp: case 13, lines 392-396
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "li":
		// Burp: case 14, lines 397-401
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "meta":
		// Burp: case 15, lines 402-406
		e.extractAttr(n, "url", ResourceHTML, baseURL, callback)

	case "note":
		// Burp: case 16, lines 407-411
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "object":
		// Burp: case 17, lines 412-418
		e.extractAttr(n, "code", ResourceBinary, baseURL, callback)
		e.extractAttr(n, "codebase", ResourceHTML, baseURL, callback)
		e.extractAttr(n, "data", ResourceBinary, baseURL, callback)

	case "ul":
		// Burp: case 18, lines 419-423
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "blockquote":
		// Burp: case 19, lines 424-428
		e.extractAttr(n, "cite", ResourceHTML, baseURL, callback)

	case "ins":
		// Burp: case 20, lines 429-433
		e.extractAttr(n, "cite", ResourceHTML, baseURL, callback)

	case "del":
		// Burp: case 21, lines 434-438
		e.extractAttr(n, "cite", ResourceHTML, baseURL, callback)

	case "video":
		// Burp: case 22, lines 439-443
		e.extractAttr(n, "src", ResourceVideo, baseURL, callback)

	case "image":
		// Burp: case 23, lines 444-450
		e.extractAttr(n, "src", ResourceImage, baseURL, callback)
		e.extractAttr(n, "href", ResourceImage, baseURL, callback)
		e.extractAttr(n, "xlink:href", ResourceImage, baseURL, callback)

	case "svg":
		// Burp: case 24, lines 451-455
		e.extractAttr(n, "src", ResourceBinary, baseURL, callback)

	case "html":
		// Burp: case 25, lines 456-460
		e.extractAttr(n, "manifest", ResourceBinary, baseURL, callback)

	case "isindex":
		// Burp: case 26, lines 461-465
		e.extractAttr(n, "src", ResourceBinary, baseURL, callback)

	case "source":
		// Burp: case 27, lines 466-470
		e.extractAttr(n, "src", ResourceBinary, baseURL, callback)

	case "table":
		// Burp: case 28, lines 471-475
		e.extractAttr(n, "background", ResourceImage, baseURL, callback)

	case "td":
		// Burp: case 29, lines 476-480
		e.extractAttr(n, "background", ResourceImage, baseURL, callback)

	case "input":
		// Burp: case 30, lines 481-488
		// Check type attribute to determine resource type
		typeAttr := getAttr(n, "type")
		resType := ResourceBinary
		if strings.EqualFold(typeAttr, "image") {
			resType = ResourceImage
		}
		e.extractAttr(n, "src", resType, baseURL, callback)

	case "feimage", "feImage": // HTML parser normalizes to feImage
		// Burp: case 31, lines 489-491
		e.extractAttr(n, "xlink:href", ResourceBinary, baseURL, callback)
	}

	return nil
}

// extractAttr extracts a URL from a single attribute.
//
// Burp mapping: ap7.a(ahe var0, String var1, hik var2, List<v2> var3, short var4, int var5, c5e var6)
// Lines 502-659
func (e *HTMLAttributeExtractor) extractAttr(n *html.Node, attrName string, resType ResourceType, baseURL *url.URL, callback LinkCallback) {
	value := getAttr(n, attrName)
	if value == "" {
		return
	}

	// Resolve and validate URL
	resolved, err := e.resolveAndValidate(value, baseURL)
	if err != nil {
		return
	}

	// Detect image type from extension if needed
	// Burp mapping: Lines 527-632
	if resType == ResourceImage {
		resType = e.detectImageType(resolved)
	}

	// Report the discovered link
	e.reportLink(n, attrName, value, resolved, resType, callback)
}

// extractSrcset handles srcset attribute which can contain multiple URLs.
//
// Format: "url1 1x, url2 2x" or "url1 480w, url2 800w"
//
// Burp mapping: Lines 320 (img srcset extraction)
func (e *HTMLAttributeExtractor) extractSrcset(n *html.Node, attrName string, resType ResourceType, baseURL *url.URL, callback LinkCallback) {
	value := getAttr(n, attrName)
	if value == "" {
		return
	}

	// Parse srcset: comma-separated list of "url descriptor"
	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Extract URL (everything before the descriptor)
		// Descriptor is space-separated: "url 2x" or "url 800w"
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}

		urlStr := fields[0] // First field is the URL

		// Resolve and validate
		resolved, err := e.resolveAndValidate(urlStr, baseURL)
		if err != nil {
			continue
		}

		// Detect image type
		if resType == ResourceImage {
			resType = e.detectImageType(resolved)
		}

		// Report the link
		e.reportLink(n, attrName, urlStr, resolved, resType, callback)
	}
}

// resolveAndValidate performs URL resolution and validation.
// Note: Does NOT check scope - caller is responsible for scope filtering.
//
// Burp mapping: Lines 508-656
func (e *HTMLAttributeExtractor) resolveAndValidate(rawURL string, baseURL *url.URL) (*url.URL, error) {
	// Normalize: trim and encode spaces
	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.ReplaceAll(rawURL, " ", "%20")

	// Validate protocol (only http/https/ws/wss allowed)
	if !e.isValidProtocol(rawURL) {
		return nil, &url.Error{Op: "parse", URL: rawURL, Err: errInvalidProtocol}
	}

	// Skip "." and ".."
	if rawURL == "." || rawURL == ".." {
		return nil, &url.Error{Op: "parse", URL: rawURL, Err: errDotPath}
	}

	// Resolve URL
	resolved, err := e.urlResolver.Resolve(baseURL, rawURL)
	if err != nil {
		return nil, err
	}

	// Skip if same as base URL
	if resolved.String() == baseURL.String() {
		return nil, &url.Error{Op: "resolve", URL: rawURL, Err: errSameAsBase}
	}

	return resolved, nil
}

// isValidProtocol checks if the URL has a valid protocol.
// Only http, https, ws, wss are allowed. Relative URLs (no protocol) are also valid.
//
// Burp mapping: Lines 513-520
func (e *HTMLAttributeExtractor) isValidProtocol(value string) bool {
	// Check first 12 characters for protocol
	if len(value) < 12 {
		return true // Might be relative URL
	}

	prefix := strings.ToLower(value[:12])
	colonPos := strings.Index(prefix, ":")
	if colonPos <= 0 {
		return true // No protocol, relative URL
	}

	proto := prefix[:colonPos]
	return proto == "http" || proto == "https" || proto == "ws" || proto == "wss"
}

// determineLinkResourceType determines the resource type for a <link> tag.
// Checks multiple attributes to detect JavaScript loading patterns:
//   - type attribute: type="text/javascript"
//   - rel + as attributes: rel="preload" as="script", rel="prefetch" as="script"
//   - rel attribute: rel="modulepreload"
//
// Modern apps commonly use these patterns:
//   - <link rel="preload" as="script" href="/app.js">
//   - <link rel="modulepreload" href="/module.mjs">
//   - <link rel="prefetch" as="script" href="/lazy.js">
func (e *HTMLAttributeExtractor) determineLinkResourceType(n *html.Node) ResourceType {
	typeAttr := strings.ToLower(getAttr(n, "type"))
	relAttr := strings.ToLower(getAttr(n, "rel"))
	asAttr := strings.ToLower(getAttr(n, "as"))

	// Check type attribute first (legacy pattern)
	if typeAttr != "" {
		if strings.Contains(typeAttr, "javascript") || strings.Contains(typeAttr, "script") {
			return ResourceScript
		}
		if strings.Contains(typeAttr, "css") || strings.Contains(typeAttr, "stylesheet") {
			return ResourceHTML
		}
		if strings.Contains(typeAttr, "image") {
			return ResourceImage
		}
	}

	// Check rel="modulepreload" (ES modules)
	if relAttr == "modulepreload" {
		return ResourceScript
	}

	// Check rel="preload/prefetch" with as="script"
	if (relAttr == "preload" || relAttr == "prefetch") && asAttr == "script" {
		return ResourceScript
	}

	// Check as="script" for other resource hints
	if asAttr == "script" {
		return ResourceScript
	}

	return ResourceHTML
}

// detectImageType detects specific image type from URL extension.
//
// Burp mapping: Lines 527-632
func (e *HTMLAttributeExtractor) detectImageType(u *url.URL) ResourceType {
	ext := strings.ToLower(filepath.Ext(u.Path))

	switch ext {
	case ".jpg", ".jpeg":
		return ResourceJPEG
	case ".gif":
		return ResourceGIF
	case ".png":
		return ResourcePNG
	case ".bmp":
		return ResourceBMP
	case ".tif", ".tiff":
		return ResourceTIFF
	default:
		return ResourceImage
	}
}

// reportLink creates a DiscoveredLink and invokes the callback.
//
// Burp mapping: Line 649 (new v2(...))
func (e *HTMLAttributeExtractor) reportLink(n *html.Node, attrName, rawURL string, resolved *url.URL, resType ResourceType, callback LinkCallback) {
	link := &DiscoveredLink{
		SourceType:   SourceHTMLAttribute,
		URL:          resolved,
		RawURL:       rawURL,
		ResourceType: resType,
		StartPos:     0, // Position tracking would require parsing offset
		EndPos:       len(rawURL),
		Element:      n.Data,
		Attribute:    attrName,
	}

	callback(link)
}

// getAttr retrieves an attribute value from an HTML node.
// Handles both regular attributes and namespaced attributes (e.g., xlink:href).
func getAttr(n *html.Node, name string) string {
	// Check for namespaced attribute (e.g., "xlink:href")
	if strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		namespace := parts[0]
		key := parts[1]

		for _, attr := range n.Attr {
			if attr.Namespace == namespace && attr.Key == key {
				return attr.Val
			}
		}
	}

	// Check for regular attribute
	for _, attr := range n.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}

	return ""
}

// Error types for validation
var (
	errInvalidProtocol = &invalidProtocolError{}
	errDotPath         = &dotPathError{}
	errSameAsBase      = &sameAsBaseError{}
)

type invalidProtocolError struct{}

func (e *invalidProtocolError) Error() string { return "invalid protocol" }

type dotPathError struct{}

func (e *dotPathError) Error() string { return "dot path" }

type sameAsBaseError struct{}

func (e *sameAsBaseError) Error() string { return "same as base" }
