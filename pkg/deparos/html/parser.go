package html

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// HTMLParsed contains all extracted HTML attributes used for fingerprinting
// Maps to Burp's ad1.java response attribute extractor (Lines 13-158)
type HTMLParsed struct {
	// Tag structure (Lines 37-52 in ad1.java)
	TagNames   []string // All HTML tag names encountered
	TagIDs     []string // All id attributes from any tag
	DivIDs     []string // id attributes specifically from <div> tags
	CSSClasses []string // All class attributes from any tag

	// Content structure (Lines 53-89)
	Title      string   // <title> tag content
	HeaderTags []string // Content from h1, h2, h3, h4, h5, h6 tags
	Comments   []string // HTML comment content

	// Link and navigation (Lines 90-115)
	AnchorLabels      []string // Text content of <a> tags
	OutboundLinkCount int      // Count of <a> tags with href
	OutboundTagNames  []string // Tag names that contain links (a, link, etc.)

	// Form elements (Lines 116-145)
	InputSubmitLabels   []string // value attribute of <input type="submit">
	ButtonSubmitLabels  []string // Text content of <button> tags
	InputImageLabels    []string // alt attribute of <input type="image">
	NonHiddenInputTypes []string // type attribute of non-hidden <input> tags

	// Raw content
	BodyContent string // Full HTML body as string
	VisibleText string // Text with tags stripped
	WordCount   int    // Total word count
	LineCount   int    // Total line count
}

// Parser handles HTML parsing for fingerprinting
// Maps to Burp's HTML parsing in ad1.java
type Parser struct{}

// NewParser creates a new HTML parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses HTML from reader and extracts all fingerprint attributes
// Maps to ad1.java:extractAttributes()
func (p *Parser) Parse(r io.Reader) (*HTMLParsed, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	return p.parseFromNode(doc), nil
}

// ParseFromNode extracts fingerprint attributes from a pre-parsed HTML node.
// Use this when you already have a parsed DOM tree (e.g., from ResponseChain.ParseHTML()).
func ParseFromNode(node *html.Node) *HTMLParsed {
	p := &Parser{}
	return p.parseFromNode(node)
}

// parseFromNode is the internal implementation for extracting attributes from a node.
func (p *Parser) parseFromNode(doc *html.Node) *HTMLParsed {
	result := &HTMLParsed{
		TagNames:            make([]string, 0),
		TagIDs:              make([]string, 0),
		DivIDs:              make([]string, 0),
		CSSClasses:          make([]string, 0),
		HeaderTags:          make([]string, 0),
		Comments:            make([]string, 0),
		AnchorLabels:        make([]string, 0),
		OutboundTagNames:    make([]string, 0),
		InputSubmitLabels:   make([]string, 0),
		ButtonSubmitLabels:  make([]string, 0),
		InputImageLabels:    make([]string, 0),
		NonHiddenInputTypes: make([]string, 0),
	}

	var bodyBuilder strings.Builder
	var visibleBuilder strings.Builder

	p.traverse(doc, result, &bodyBuilder, &visibleBuilder)

	// Store raw content
	result.BodyContent = bodyBuilder.String()
	result.VisibleText = visibleBuilder.String()

	// Calculate counts
	result.WordCount = countWords(result.VisibleText)
	result.LineCount = countLines(result.BodyContent)

	return result
}

// traverse recursively walks the HTML tree and extracts attributes
// Maps to Burp's recursive DOM traversal in ad1.java:processNode()
func (p *Parser) traverse(n *html.Node, result *HTMLParsed, bodyBuilder, visibleBuilder *strings.Builder) {
	if n.Type == html.ElementNode {
		// Record tag name
		tagName := strings.ToLower(n.Data)
		result.TagNames = append(result.TagNames, tagName)

		// Write tag to body content
		bodyBuilder.WriteString("<")
		bodyBuilder.WriteString(tagName)

		// Extract attributes
		for _, attr := range n.Attr {
			// Write attribute to body
			bodyBuilder.WriteString(" ")
			bodyBuilder.WriteString(attr.Key)
			bodyBuilder.WriteString("=\"")
			bodyBuilder.WriteString(attr.Val)
			bodyBuilder.WriteString("\"")

			// Process specific attributes
			switch strings.ToLower(attr.Key) {
			case "id":
				result.TagIDs = append(result.TagIDs, attr.Val)
				if tagName == "div" {
					result.DivIDs = append(result.DivIDs, attr.Val)
				}
			case "class":
				// Split multiple classes
				classes := strings.Fields(attr.Val)
				result.CSSClasses = append(result.CSSClasses, classes...)
			case "href":
				if tagName == "a" {
					result.OutboundLinkCount++
					if !contains(result.OutboundTagNames, tagName) {
						result.OutboundTagNames = append(result.OutboundTagNames, tagName)
					}
				}
			case "type":
				if tagName == "input" {
					inputType := strings.ToLower(attr.Val)
					if inputType != "hidden" {
						result.NonHiddenInputTypes = append(result.NonHiddenInputTypes, inputType)
					}
					// Extract submit button labels
					if inputType == "submit" {
						for _, a := range n.Attr {
							if strings.EqualFold(a.Key, "value") {
								result.InputSubmitLabels = append(result.InputSubmitLabels, a.Val)
								break
							}
						}
					}
					// Extract image input labels
					if inputType == "image" {
						for _, a := range n.Attr {
							if strings.EqualFold(a.Key, "alt") {
								result.InputImageLabels = append(result.InputImageLabels, a.Val)
								break
							}
						}
					}
				}
			}
		}

		bodyBuilder.WriteString(">")

		// Extract tag-specific content
		switch tagName {
		case "title":
			result.Title = extractText(n)
		case "h1", "h2", "h3", "h4", "h5", "h6":
			headerText := extractText(n)
			if headerText != "" {
				result.HeaderTags = append(result.HeaderTags, headerText)
			}
		case "a":
			anchorText := extractText(n)
			if anchorText != "" {
				result.AnchorLabels = append(result.AnchorLabels, anchorText)
			}
		case "button":
			buttonText := extractText(n)
			if buttonText != "" {
				result.ButtonSubmitLabels = append(result.ButtonSubmitLabels, buttonText)
			}
		}

		// Skip script and style content for visible text
		if tagName != "script" && tagName != "style" {
			// Traverse children
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				p.traverse(c, result, bodyBuilder, visibleBuilder)
			}
		} else {
			// Still traverse for body content but skip visible text
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				p.traverseBody(c, bodyBuilder)
			}
		}

		// Close tag
		bodyBuilder.WriteString("</")
		bodyBuilder.WriteString(tagName)
		bodyBuilder.WriteString(">")

	} else if n.Type == html.TextNode {
		text := n.Data
		bodyBuilder.WriteString(text)

		// Add to visible text if not empty/whitespace
		trimmed := strings.TrimSpace(text)
		if trimmed != "" {
			if visibleBuilder.Len() > 0 {
				visibleBuilder.WriteString(" ")
			}
			visibleBuilder.WriteString(trimmed)
		}

	} else if n.Type == html.CommentNode {
		result.Comments = append(result.Comments, n.Data)
		bodyBuilder.WriteString("<!--")
		bodyBuilder.WriteString(n.Data)
		bodyBuilder.WriteString("-->")

	} else if n.Type == html.DocumentNode {
		// Root node - traverse children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			p.traverse(c, result, bodyBuilder, visibleBuilder)
		}
	}
}

// traverseBody traverses only for body content (skips visible text extraction)
func (p *Parser) traverseBody(n *html.Node, bodyBuilder *strings.Builder) {
	switch n.Type {
	case html.ElementNode:
		tagName := strings.ToLower(n.Data)
		bodyBuilder.WriteString("<")
		bodyBuilder.WriteString(tagName)

		for _, attr := range n.Attr {
			bodyBuilder.WriteString(" ")
			bodyBuilder.WriteString(attr.Key)
			bodyBuilder.WriteString("=\"")
			bodyBuilder.WriteString(attr.Val)
			bodyBuilder.WriteString("\"")
		}

		bodyBuilder.WriteString(">")

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			p.traverseBody(c, bodyBuilder)
		}

		bodyBuilder.WriteString("</")
		bodyBuilder.WriteString(tagName)
		bodyBuilder.WriteString(">")

	case html.TextNode:
		bodyBuilder.WriteString(n.Data)
	case html.CommentNode:
		bodyBuilder.WriteString("<!--")
		bodyBuilder.WriteString(n.Data)
		bodyBuilder.WriteString("-->")
	}
}

// extractText extracts all text content from a node and its children
func extractText(n *html.Node) string {
	var builder strings.Builder
	extractTextRecursive(n, &builder)
	return strings.TrimSpace(builder.String())
}

func extractTextRecursive(n *html.Node, builder *strings.Builder) {
	if n.Type == html.TextNode {
		text := strings.TrimSpace(n.Data)
		if text != "" {
			if builder.Len() > 0 {
				builder.WriteString(" ")
			}
			builder.WriteString(text)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		extractTextRecursive(c, builder)
	}
}

// countWords counts words in text (splits on whitespace)
// Maps to Burp's word counting in ad1.java
func countWords(text string) int {
	if text == "" {
		return 0
	}
	words := strings.Fields(text)
	return len(words)
}

// countLines counts lines in text
// Maps to Burp's line counting in ad1.java
func countLines(text string) int {
	if text == "" {
		return 0
	}
	lines := strings.Split(text, "\n")
	return len(lines)
}

// contains checks if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
