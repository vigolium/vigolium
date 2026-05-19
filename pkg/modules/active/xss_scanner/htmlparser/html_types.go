package htmlparser

import (
	"fmt"
	"strings"
)

// ParseMode defines the HTML parsing modes.
type ParseMode int

const (
	// ParseModeNone performs no special parsing.
	ParseModeNone ParseMode = iota
	// ParseModeHead parses only up to the closing </head> tag.
	ParseModeHead
	// ParseModeFull parses the entire document.
	ParseModeFull
)

type QuoteType byte

const (
	QuoteTypeDouble QuoteType = iota
	QuoteTypeSingle
	QuoteTypeBacktick
	QuoteTypeNone
)

func (q QuoteType) String() string {
	switch q {
	case QuoteTypeDouble:
		return "Double"
	case QuoteTypeSingle:
		return "Single"
	case QuoteTypeBacktick:
		return "Backtick"
	case QuoteTypeNone:
		return "None"
	default:
		return "Unknown"
	}
}

// HTMLAttribute represents an attribute of an HTML tag.
type HTMLAttribute struct {
	Name       string
	Value      string
	NameStart  int
	NameEnd    int
	ValueStart int
	ValueEnd   int
	QuoteType  QuoteType // 0: double ("), 1: single ('), 2: backtick (`), 3: none
}

// HTMLTagInfo contains information about an HTML tag.
type HTMLTagInfo struct {
	Name       string // Tag name, lowercased
	NameStart  int    // Start position of the tag name (after '<' or '</')
	NameEnd    int    // End position of the tag name
	Attributes []*HTMLAttribute
}

func (t *HTMLTagInfo) GetAttribute(name string) string {
	for _, attr := range t.Attributes {
		if strings.EqualFold(attr.Name, name) {
			return attr.Value
		}
	}
	return ""
}

func (t *HTMLTagInfo) String() string {
	return fmt.Sprintf(
		"HTMLTagInfo{Name: %s, NameStart: %d, NameEnd: %d, Attributes: %d}",
		t.Name,
		t.NameStart,
		t.NameEnd,
		len(t.Attributes),
	)
}

// HTMLElementType defines the type of an HTML element.
type HTMLElementType byte

const (
	// OpenTag is an opening tag (e.g., <div>).
	OpenTag HTMLElementType = 0
	// CloseTag is a closing tag (e.g., </div>).
	CloseTag HTMLElementType = 1
	// CommentOrDirective is a comment (<!-- ... -->) or directive (<!...>).
	CommentOrDirective HTMLElementType = 2
	// TextNode is a text node.
	TextNode HTMLElementType = 3
	// SelfClosingTagOrPI is a self-closing tag (e.g., <br/>, <img/>)
	// or a processing instruction (e.g., <?xml ... ?>).
	SelfClosingTagOrPI HTMLElementType = 4
)

func (h HTMLElementType) String() string {
	switch h {
	case OpenTag:
		return "OpenTag"
	case CloseTag:
		return "CloseTag"
	case CommentOrDirective:
		return "CommentOrDirective"
	case TextNode:
		return "TextNode"
	case SelfClosingTagOrPI:
		return "SelfClosingTagOrPI"
	default:
		return "Unknown"
	}
}

// HTMLElement represents an element in the HTML tree.
type HTMLElement struct {
	Type HTMLElementType
	// TagInfo is set when Type is OpenTag, CloseTag, or SelfClosingTagOrPI.
	TagInfo *HTMLTagInfo
	// Content is set when Type is TextNode or CommentOrDirective.
	// For CommentOrDirective, Content includes the full markup (e.g., <!-- and -->).
	// For TextNode, Content is the text with HTML entities decoded.
	Content     string
	StartOffset int
	EndOffset   int
}

func NewHTMLElement(
	var1 int,
	var2 int,
	var3 HTMLElementType,
	var4 *HTMLTagInfo,
	var5 string,
) *HTMLElement {
	return &HTMLElement{
		StartOffset: var1,
		EndOffset:   var2,
		Type:        var3,
		TagInfo:     var4,
		Content:     var5,
	}
}

func (h *HTMLElement) String() string {
	tagInfoString := "nil"
	if h.TagInfo != nil {
		tagInfoString = h.TagInfo.String()
	}
	return fmt.Sprintf(
		"HTMLElement{Type: %s, TagInfo: %s, Content: %s, StartOffset: %d, EndOffset: %d}",
		h.Type.String(),
		tagInfoString,
		h.Content,
		h.StartOffset,
		h.EndOffset,
	)
}
