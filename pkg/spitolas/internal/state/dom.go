package state

import (
	"bytes"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// Whitespace-normalization patterns, compiled once. normalizeWhitespace runs on
// every captured DOM state and every URL reload, so compiling these per call was
// pure overhead.
var (
	reStripControlWS = regexp.MustCompile(`[\t\n\x0B\f\r]+`)
	reSpaceAfterGt   = regexp.MustCompile(`>[ ]+`)
	reSpaceBeforeLt  = regexp.MustCompile(`[ ]+<`)
)

// attrPatternCache memoizes the compiled attribute-strip patterns keyed on the
// attribute list, so the default set (and any fixed comparator set) is compiled
// once for the whole crawl rather than ~4 regexes per StripDOM call.
var attrPatternCache sync.Map // key: joined stripAttrs → []*regexp.Regexp

func compileAttrPatterns(stripAttrs []string) []*regexp.Regexp {
	key := strings.Join(stripAttrs, "\x00")
	if v, ok := attrPatternCache.Load(key); ok {
		return v.([]*regexp.Regexp)
	}
	patterns := make([]*regexp.Regexp, 0, len(stripAttrs))
	for _, attr := range stripAttrs {
		var pattern string
		if strings.Contains(attr, "*") {
			// Convert glob pattern to regex
			pattern = "^" + strings.ReplaceAll(regexp.QuoteMeta(attr), "\\*", ".*") + "$"
		} else {
			// Exact match
			pattern = "^" + regexp.QuoteMeta(attr) + "$"
		}
		if re, err := regexp.Compile(pattern); err == nil {
			patterns = append(patterns, re)
		}
	}
	attrPatternCache.Store(key, patterns)
	return patterns
}

// DefaultStripTags are tags removed before comparison.
var DefaultStripTags = []string{
	"script",
	"style",
	"noscript",
	"meta",
	"link",
}

// DefaultStripAttrs are attributes removed before comparison.
var DefaultStripAttrs = []string{
	"id",
	"class",
	"style",
	"data-*",
}

// StripDOM normalizes HTML for state comparison.
// 1. Parse HTML
// 2. Remove specified tags entirely
// 3. Remove specified attributes
// 4. Normalize whitespace
// 5. Render back to string
func StripDOM(rawHTML string, stripTags, stripAttrs []string) string {
	if rawHTML == "" {
		return ""
	}

	// Parse HTML
	doc, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		// If parsing fails, fallback to regex-based stripping
		return stripDOMFallback(rawHTML, stripTags, stripAttrs)
	}

	// Build set of tags to strip
	tagSet := make(map[string]bool)
	for _, tag := range stripTags {
		tagSet[strings.ToLower(tag)] = true
	}

	// Build (memoized) patterns for attributes to strip
	attrPatterns := compileAttrPatterns(stripAttrs)

	// Process the DOM tree
	stripNode(doc, tagSet, attrPatterns)

	// Render back to string
	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return stripDOMFallback(rawHTML, stripTags, stripAttrs)
	}

	result := buf.String()

	// Normalize whitespace
	result = normalizeWhitespace(result)

	return result
}

// stripNode recursively processes nodes, removing specified tags and attributes.
func stripNode(n *html.Node, stripTags map[string]bool, attrPatterns []*regexp.Regexp) {
	if n == nil {
		return
	}

	// Process children first (in reverse to handle removals)
	var toRemove []*html.Node
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && stripTags[strings.ToLower(c.Data)] {
			toRemove = append(toRemove, c)
		} else {
			stripNode(c, stripTags, attrPatterns)
		}
	}

	// Remove marked nodes
	for _, c := range toRemove {
		n.RemoveChild(c)
	}

	// Strip attributes from element nodes
	if n.Type == html.ElementNode {
		n.Attr = filterAttributes(n.Attr, attrPatterns)
	}
}

// filterAttributes removes attributes matching the patterns.
func filterAttributes(attrs []html.Attribute, patterns []*regexp.Regexp) []html.Attribute {
	if len(patterns) == 0 {
		return attrs
	}

	filtered := make([]html.Attribute, 0, len(attrs))
	for _, attr := range attrs {
		keep := true
		for _, pattern := range patterns {
			if pattern.MatchString(attr.Key) {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, attr)
		}
	}

	return filtered
}

// 1. Removes [\t\n\x0B\f\r] (tab, newline, vertical-tab, form-feed, carriage-return)
// 2. ">[ ]*" → ">" (removes spaces after closing angle bracket)
// 3. "[ ]*<" → "<" (removes spaces before opening angle bracket)
// 4. Interior text spacing is PRESERVED ("hello   world" stays)
func normalizeWhitespace(s string) string {
	// Step 1: Remove control whitespace (tab, newline, form-feed, carriage-return, vertical-tab)
	// but preserve regular spaces within text content
	s = reStripControlWS.ReplaceAllString(s, "")

	// Step 2: Remove spaces immediately after closing angle bracket: ">[ ]*" → ">"
	s = reSpaceAfterGt.ReplaceAllString(s, ">")

	// Step 3: Remove spaces immediately before opening angle bracket: "[ ]*<" → "<"
	s = reSpaceBeforeLt.ReplaceAllString(s, "<")

	// Trim
	s = strings.TrimSpace(s)

	return s
}

// stripDOMFallback uses regex-based stripping when parsing fails.
func stripDOMFallback(rawHTML string, stripTags, stripAttrs []string) string {
	result := rawHTML

	// Remove tags
	for _, tag := range stripTags {
		// Remove opening and closing tags with content
		pattern := regexp.MustCompile(`(?is)<` + regexp.QuoteMeta(tag) + `[^>]*>.*?</` + regexp.QuoteMeta(tag) + `>`)
		result = pattern.ReplaceAllString(result, "")

		// Remove self-closing tags
		pattern = regexp.MustCompile(`(?i)<` + regexp.QuoteMeta(tag) + `[^>]*/?>`)
		result = pattern.ReplaceAllString(result, "")
	}

	// Remove attributes
	for _, attr := range stripAttrs {
		if strings.Contains(attr, "*") {
			// Glob pattern
			attrPrefix := strings.TrimSuffix(attr, "*")
			pattern := regexp.MustCompile(`(?i)\s+` + regexp.QuoteMeta(attrPrefix) + `[a-z0-9_-]*\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
			result = pattern.ReplaceAllString(result, "")
		} else {
			// Exact match
			pattern := regexp.MustCompile(`(?i)\s+` + regexp.QuoteMeta(attr) + `\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
			result = pattern.ReplaceAllString(result, "")
		}
	}

	// Normalize whitespace
	result = normalizeWhitespace(result)

	return result
}

// StripDOMDefault strips DOM using default tags and attributes.
func StripDOMDefault(rawHTML string) string {
	return StripDOM(rawHTML, DefaultStripTags, DefaultStripAttrs)
}

// ExtractBodyContent extracts the content of the body tag.
func ExtractBodyContent(rawHTML string) string {
	doc, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		return rawHTML
	}

	var body *html.Node
	var findBody func(*html.Node)
	findBody = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "body" {
			body = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findBody(c)
			if body != nil {
				return
			}
		}
	}
	findBody(doc)

	if body == nil {
		return rawHTML
	}

	var buf bytes.Buffer
	for c := body.FirstChild; c != nil; c = c.NextSibling {
		_ = html.Render(&buf, c)
	}

	return buf.String()
}

// ExtractTextContent extracts text content from HTML.
func ExtractTextContent(rawHTML string) string {
	doc, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		return ""
	}

	var buf bytes.Buffer
	var extractText func(*html.Node)
	extractText = func(n *html.Node) {
		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
				buf.WriteString(text)
				buf.WriteString(" ")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractText(c)
		}
	}
	extractText(doc)

	return strings.TrimSpace(buf.String())
}

// CountNodes counts the number of nodes in HTML.
func CountNodes(rawHTML string) int {
	doc, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		return 0
	}

	count := 0
	var countNodes func(*html.Node)
	countNodes = func(n *html.Node) {
		count++
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			countNodes(c)
		}
	}
	countNodes(doc)

	return count
}

// GetTitle extracts the title from HTML.
func GetTitle(rawHTML string) string {
	doc, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		return ""
	}

	var title string
	var findTitle func(*html.Node)
	findTitle = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				title = strings.TrimSpace(n.FirstChild.Data)
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if title != "" {
				return
			}
			findTitle(c)
		}
	}
	findTitle(doc)

	return title
}
