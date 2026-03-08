package xss_light_scanner

import (
	"bytes"
	"strings"
)

// Void tags (self-closing in HTML mode)
var voidTags = map[string]bool{
	"img": true, "br": true, "hr": true, "meta": true, "input": true,
	"link": true, "area": true, "base": true, "col": true, "embed": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

// Raw text tags - content is not parsed as HTML
var rawTextTags = map[string]bool{
	"script": true, "style": true, "xmp": true, "textarea": true,
	"title": true, "noscript": true, "plaintext": true,
}

// HtmlParser parses HTML with byte-level precision and offset tracking
type HtmlParser struct {
	data        []byte
	pos         int
	end         int
	inScript    bool
	inRawText   bool
	rawTextTag  string
	elements    []*HtmlElement
	parentStack []string
}

// NewHtmlParser creates a new HTML parser
func NewHtmlParser(data []byte) *HtmlParser {
	return &HtmlParser{
		data:        data,
		pos:         0,
		end:         len(data),
		elements:    make([]*HtmlElement, 0),
		parentStack: make([]string, 0),
	}
}

// Parse parses the HTML and returns all elements
func (p *HtmlParser) Parse() []*HtmlElement {
	for p.pos < p.end {
		textStart := p.pos
		p.skipUntilTag()

		// If we found text before the tag
		if p.pos > textStart {
			content := p.data[textStart:p.pos]
			if len(bytes.TrimSpace(content)) > 0 {
				elem := &HtmlElement{
					Type:        ElementText,
					StartOffset: textStart,
					EndOffset:   p.pos,
					Content:     content,
					InScript:    p.inScript,
					ParentTag:   p.currentParent(),
				}
				p.elements = append(p.elements, elem)
			}
		}

		// Parse tag if we're at '<' and not at end
		if p.pos < p.end && p.data[p.pos] == '<' {
			p.parseTag()
		}
	}

	return p.elements
}

// currentParent returns the current parent tag name
func (p *HtmlParser) currentParent() string {
	if len(p.parentStack) > 0 {
		return p.parentStack[len(p.parentStack)-1]
	}
	return ""
}

// skipUntilTag skips forward until '<' found, respecting raw text boundaries
func (p *HtmlParser) skipUntilTag() {
	for p.pos < p.end {
		if p.data[p.pos] == '<' {
			if p.inRawText {
				// Only stop at closing tag for current raw text element
				closeTag := "</" + p.rawTextTag
				if p.startsWithIgnoreCase(p.pos, closeTag) {
					break
				}
			} else {
				break
			}
		}
		p.pos++
	}
}

// parseTag parses a tag starting at current '<' position
func (p *HtmlParser) parseTag() {
	tagStart := p.pos
	p.pos++ // Skip '<'

	if p.pos >= p.end {
		return
	}

	// Check for comment or directive
	if p.data[p.pos] == '!' {
		p.parseCommentOrDirective(tagStart)
		return
	}

	// Determine tag type
	var tagType HtmlElementType
	if p.data[p.pos] == '/' {
		tagType = ElementCloseTag
		p.pos++ // Skip '/'
	} else {
		tagType = ElementOpenTag
	}

	// Parse tag name
	nameStart := p.pos
	for p.pos < p.end && p.isTagNameChar(p.data[p.pos]) {
		p.pos++
	}
	nameEnd := p.pos

	if nameStart == nameEnd {
		// No tag name, skip to '>'
		for p.pos < p.end && p.data[p.pos] != '>' {
			p.pos++
		}
		if p.pos < p.end {
			p.pos++ // Skip '>'
		}
		return
	}

	tagName := strings.ToLower(string(p.data[nameStart:nameEnd]))

	elem := &HtmlElement{
		Type:        tagType,
		StartOffset: tagStart,
		TagName:     tagName,
		Attributes:  make([]*HtmlAttribute, 0),
		InScript:    p.inScript,
		ParentTag:   p.currentParent(),
	}

	// Parse attributes (only for open tags)
	if tagType == ElementOpenTag {
		p.parseAttributes(elem)
	} else {
		// Skip to '>' for close tags
		for p.pos < p.end && p.data[p.pos] != '>' {
			p.pos++
		}
	}

	// Find closing '>' or '/>'
	selfClosing := false
	for p.pos < p.end {
		if p.data[p.pos] == '/' {
			if p.pos+1 < p.end && p.data[p.pos+1] == '>' {
				selfClosing = true
				p.pos += 2 // Skip '/>'
				break
			}
		} else if p.data[p.pos] == '>' {
			p.pos++ // Skip '>'
			break
		}
		p.pos++
	}

	elem.EndOffset = p.pos

	// Determine final tag type and update parser state
	switch tagType {
	case ElementOpenTag:
		if selfClosing || voidTags[tagName] {
			elem.Type = ElementSelfClosing
		} else {
			// Track parent stack
			p.parentStack = append(p.parentStack, tagName)

			// Track raw text tags
			if rawTextTags[tagName] {
				p.inRawText = true
				p.rawTextTag = tagName
				if tagName == "script" {
					p.inScript = true
				}
			}
		}
	case ElementCloseTag:
		// Pop from parent stack
		if len(p.parentStack) > 0 && p.parentStack[len(p.parentStack)-1] == tagName {
			p.parentStack = p.parentStack[:len(p.parentStack)-1]
		}

		// Exit raw text mode
		if p.rawTextTag == tagName {
			p.inRawText = false
			p.rawTextTag = ""
			if tagName == "script" {
				p.inScript = false
			}
		}
	}

	p.elements = append(p.elements, elem)
}

// parseAttributes parses tag attributes
func (p *HtmlParser) parseAttributes(elem *HtmlElement) {
	for p.pos < p.end {
		// Skip whitespace
		for p.pos < p.end && p.isWhitespace(p.data[p.pos]) {
			p.pos++
		}

		// Check for end of tag
		if p.pos >= p.end || p.data[p.pos] == '>' || p.data[p.pos] == '/' {
			break
		}

		// Parse attribute name
		attrNameStart := p.pos
		for p.pos < p.end && p.isAttributeNameChar(p.data[p.pos]) {
			p.pos++
		}
		attrNameEnd := p.pos

		if attrNameStart == attrNameEnd {
			// Skip invalid character
			p.pos++
			continue
		}

		attrName := string(p.data[attrNameStart:attrNameEnd])

		attr := &HtmlAttribute{
			Name:      attrName,
			NameStart: attrNameStart,
			NameEnd:   attrNameEnd,
			QuoteType: QuoteNone,
		}

		// Skip whitespace after name
		for p.pos < p.end && p.isWhitespace(p.data[p.pos]) {
			p.pos++
		}

		// Check for '='
		if p.pos < p.end && p.data[p.pos] == '=' {
			p.pos++ // Skip '='

			// Skip whitespace after '='
			for p.pos < p.end && p.isWhitespace(p.data[p.pos]) {
				p.pos++
			}

			// Parse attribute value
			if p.pos < p.end {
				firstChar := p.data[p.pos]

				switch firstChar {
				case '"':
					attr.QuoteType = QuoteDouble
					p.pos++ // Skip opening quote
					attr.ValueStart = p.pos
					p.findClosingQuote('"')
					attr.ValueEnd = p.pos
					if p.pos < p.end && p.data[p.pos] == '"' {
						p.pos++ // Skip closing quote
					}
				case '\'':
					attr.QuoteType = QuoteSingle
					p.pos++ // Skip opening quote
					attr.ValueStart = p.pos
					p.findClosingQuote('\'')
					attr.ValueEnd = p.pos
					if p.pos < p.end && p.data[p.pos] == '\'' {
						p.pos++ // Skip closing quote
					}
				case '`':
					attr.QuoteType = QuoteBacktick
					p.pos++ // Skip opening quote
					attr.ValueStart = p.pos
					p.findClosingQuote('`')
					attr.ValueEnd = p.pos
					if p.pos < p.end && p.data[p.pos] == '`' {
						p.pos++ // Skip closing quote
					}
				default:
					// Unquoted value
					attr.QuoteType = QuoteNone
					attr.ValueStart = p.pos
					for p.pos < p.end && p.isUnquotedValueChar(p.data[p.pos]) {
						p.pos++
					}
					attr.ValueEnd = p.pos
				}

				attr.Value = string(p.data[attr.ValueStart:attr.ValueEnd])
			}
		}

		elem.Attributes = append(elem.Attributes, attr)
	}
}

// findClosingQuote advances pos to the closing quote character
func (p *HtmlParser) findClosingQuote(quoteChar byte) {
	for p.pos < p.end && p.data[p.pos] != quoteChar {
		p.pos++
	}
}

// parseCommentOrDirective parses comments (<!--) or directives (<!DOCTYPE)
func (p *HtmlParser) parseCommentOrDirective(tagStart int) {
	p.pos++ // Skip '!'

	elemType := ElementDirective

	// Check for proper comment (<!--)
	if p.startsWith(p.pos, "--") {
		elemType = ElementComment
		p.pos += 2 // Skip '--'
		end := p.indexOf("-->", p.pos)
		if end != -1 {
			p.pos = end + 3
		} else {
			p.pos = p.end
		}
	} else if p.startsWithIgnoreCase(p.pos, "[CDATA[") {
		// CDATA section
		elemType = ElementCDATA
		p.pos += 7 // Skip '[CDATA['
		end := p.indexOf("]]>", p.pos)
		if end != -1 {
			p.pos = end + 3
		} else {
			p.pos = p.end
		}
	} else {
		// Directive (<!DOCTYPE, etc.)
		for p.pos < p.end && p.data[p.pos] != '>' {
			p.pos++
		}
		if p.pos < p.end {
			p.pos++ // Skip '>'
		}
	}

	elem := &HtmlElement{
		Type:        elemType,
		StartOffset: tagStart,
		EndOffset:   p.pos,
		Content:     p.data[tagStart:p.pos],
		InScript:    p.inScript,
		ParentTag:   p.currentParent(),
	}
	p.elements = append(p.elements, elem)
}

// Helper methods

func (p *HtmlParser) isTagNameChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '_' || b == ':'
}

func (p *HtmlParser) isAttributeNameChar(b byte) bool {
	return !p.isWhitespace(b) && b != '=' && b != '>' && b != '/' && b != '<'
}

func (p *HtmlParser) isUnquotedValueChar(b byte) bool {
	return !p.isWhitespace(b) && b != '>' && b != '<'
}

func (p *HtmlParser) isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func (p *HtmlParser) startsWith(offset int, prefix string) bool {
	if offset+len(prefix) > p.end {
		return false
	}
	return string(p.data[offset:offset+len(prefix)]) == prefix
}

func (p *HtmlParser) startsWithIgnoreCase(offset int, prefix string) bool {
	if offset+len(prefix) > p.end {
		return false
	}
	return strings.EqualFold(string(p.data[offset:offset+len(prefix)]), prefix)
}

func (p *HtmlParser) indexOf(needle string, fromIndex int) int {
	needleBytes := []byte(needle)
	idx := bytes.Index(p.data[fromIndex:p.end], needleBytes)
	if idx == -1 {
		return -1
	}
	return fromIndex + idx
}

// ParseHTML is a convenience function to parse HTML bytes
func ParseHTML(data []byte) []*HtmlElement {
	parser := NewHtmlParser(data)
	return parser.Parse()
}

// FindElementAtOffset finds the element containing the given offset
func FindElementAtOffset(elements []*HtmlElement, offset int) *HtmlElement {
	for _, elem := range elements {
		if elem.ContainsOffset(offset) {
			return elem
		}
	}
	return nil
}

// FindElementsInRange finds all elements within the given range
func FindElementsInRange(elements []*HtmlElement, start, end int) []*HtmlElement {
	var result []*HtmlElement
	for _, elem := range elements {
		if elem.StartOffset < end && elem.EndOffset > start {
			result = append(result, elem)
		}
	}
	return result
}
