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
// Supported elements (32 tags):
//   - a, img, script, link, applet, area, base, bgsound, sound, body
//   - embed, frame, fig, iframe, li, meta, note, object, ul, blockquote
//   - ins, del, video, image, svg, html, isindex, source, table, td
//   - input, feimage
//
// Note: This extractor does NOT check scope. Caller is responsible for scope filtering.
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
func (e *HTMLAttributeExtractor) extractFromElement(n *html.Node, baseURL *url.URL, tagName string, callback LinkCallback) *url.URL {
	// Map tag names to their attributes and resource types
	switch tagName {
	case "a":
		e.extractAttr(n, "href", ResourceHTML, baseURL, callback)

	case "img":
		e.extractAttr(n, "src", ResourceImage, baseURL, callback)
		e.extractSrcset(n, "srcset", ResourceImage, baseURL, callback)

	case "script":
		e.extractAttr(n, "src", ResourceScript, baseURL, callback)
		e.extractAttr(n, "xlink:href", ResourceScript, baseURL, callback)

	case "link":
		// Determine resource type from type, rel, and as attributes
		// Modern apps use: <link rel="preload" as="script">, <link rel="modulepreload">
		resType := e.determineLinkResourceType(n)
		e.extractAttr(n, "href", resType, baseURL, callback)
		e.extractAttr(n, "src", resType, baseURL, callback)

	case "applet":
		e.extractAttr(n, "code", ResourceBinary, baseURL, callback)
		e.extractAttr(n, "codebase", ResourceHTML, baseURL, callback)
		e.extractAttr(n, "archive", ResourceBinary, baseURL, callback)
		e.extractAttr(n, "object", ResourceBinary, baseURL, callback)

	case "area":
		e.extractAttr(n, "href", ResourceHTML, baseURL, callback)

	case "base":
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
		e.extractAttr(n, "src", ResourceAudio, baseURL, callback)

	case "sound":
		e.extractAttr(n, "src", ResourceAudio, baseURL, callback)

	case "body":
		e.extractAttr(n, "background", ResourceImage, baseURL, callback)
		e.extractAttr(n, "location", ResourceHTML, baseURL, callback)

	case "embed":
		e.extractAttr(n, "src", ResourceBinary, baseURL, callback)
		e.extractAttr(n, "code", ResourceBinary, baseURL, callback)

	case "frame":
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "fig":
		e.extractAttr(n, "src", ResourceImage, baseURL, callback)

	case "iframe":
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "li":
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "meta":
		e.extractAttr(n, "url", ResourceHTML, baseURL, callback)

	case "note":
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "object":
		e.extractAttr(n, "code", ResourceBinary, baseURL, callback)
		e.extractAttr(n, "codebase", ResourceHTML, baseURL, callback)
		e.extractAttr(n, "data", ResourceBinary, baseURL, callback)

	case "ul":
		e.extractAttr(n, "src", ResourceHTML, baseURL, callback)

	case "blockquote":
		e.extractAttr(n, "cite", ResourceHTML, baseURL, callback)

	case "ins":
		e.extractAttr(n, "cite", ResourceHTML, baseURL, callback)

	case "del":
		e.extractAttr(n, "cite", ResourceHTML, baseURL, callback)

	case "video":
		e.extractAttr(n, "src", ResourceVideo, baseURL, callback)

	case "image":
		e.extractAttr(n, "src", ResourceImage, baseURL, callback)
		e.extractAttr(n, "href", ResourceImage, baseURL, callback)
		e.extractAttr(n, "xlink:href", ResourceImage, baseURL, callback)

	case "svg":
		e.extractAttr(n, "src", ResourceBinary, baseURL, callback)

	case "html":
		e.extractAttr(n, "manifest", ResourceBinary, baseURL, callback)

	case "isindex":
		e.extractAttr(n, "src", ResourceBinary, baseURL, callback)

	case "source":
		e.extractAttr(n, "src", ResourceBinary, baseURL, callback)

	case "table":
		e.extractAttr(n, "background", ResourceImage, baseURL, callback)

	case "td":
		e.extractAttr(n, "background", ResourceImage, baseURL, callback)

	case "input":
		// Check type attribute to determine resource type
		typeAttr := getAttr(n, "type")
		resType := ResourceBinary
		if strings.EqualFold(typeAttr, "image") {
			resType = ResourceImage
		}
		e.extractAttr(n, "src", resType, baseURL, callback)

	case "feimage", "feImage": // HTML parser normalizes to feImage
		e.extractAttr(n, "xlink:href", ResourceBinary, baseURL, callback)
	}

	return nil
}

// extractAttr extracts a URL from a single attribute.
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
	if resType == ResourceImage {
		resType = e.detectImageType(resolved)
	}

	// Report the discovered link
	e.reportLink(n, attrName, value, resolved, resType, callback)
}

// extractSrcset handles srcset attribute which can contain multiple URLs.
//
// Format: "url1 1x, url2 2x" or "url1 480w, url2 800w"
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
