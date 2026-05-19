package xss_light_scanner

// QuoteType represents the quote style used in HTML attributes
type QuoteType int

const (
	QuoteNone QuoteType = iota
	QuoteDouble
	QuoteSingle
	QuoteBacktick
)

func (q QuoteType) String() string {
	switch q {
	case QuoteDouble:
		return "double"
	case QuoteSingle:
		return "single"
	case QuoteBacktick:
		return "backtick"
	default:
		return "none"
	}
}

// HtmlElementType represents the type of HTML element
type HtmlElementType int

const (
	ElementText HtmlElementType = iota
	ElementOpenTag
	ElementCloseTag
	ElementSelfClosing
	ElementComment
	ElementDirective
	ElementCDATA
)

func (t HtmlElementType) String() string {
	switch t {
	case ElementText:
		return "text"
	case ElementOpenTag:
		return "open_tag"
	case ElementCloseTag:
		return "close_tag"
	case ElementSelfClosing:
		return "self_closing"
	case ElementComment:
		return "comment"
	case ElementDirective:
		return "directive"
	case ElementCDATA:
		return "cdata"
	default:
		return "unknown"
	}
}

// HtmlAttribute represents an HTML attribute with offset tracking
type HtmlAttribute struct {
	Name       string
	Value      string
	QuoteType  QuoteType
	NameStart  int
	NameEnd    int
	ValueStart int
	ValueEnd   int
}

// ContainsOffset checks if the given offset is within this attribute's value
func (a *HtmlAttribute) ContainsOffset(offset int) bool {
	return offset >= a.ValueStart && offset < a.ValueEnd
}

// ContainsNameOffset checks if the given offset is within this attribute's name
func (a *HtmlAttribute) ContainsNameOffset(offset int) bool {
	return offset >= a.NameStart && offset < a.NameEnd
}

// HtmlElement represents a parsed HTML element with offset tracking
type HtmlElement struct {
	Type        HtmlElementType
	StartOffset int
	EndOffset   int
	TagName     string
	Attributes  []*HtmlAttribute
	Content     []byte // decoded content for TEXT elements
	InScript    bool   // true if this element is inside a <script> tag
	ParentTag   string // parent tag name for context (e.g., "script", "xmp", "title")
}

// ContainsOffset checks if the given offset is within this element
func (e *HtmlElement) ContainsOffset(offset int) bool {
	return offset >= e.StartOffset && offset < e.EndOffset
}

// FindAttributeAtOffset returns the attribute containing the given offset, or nil
func (e *HtmlElement) FindAttributeAtOffset(offset int) *HtmlAttribute {
	for _, attr := range e.Attributes {
		if attr.ContainsOffset(offset) || attr.ContainsNameOffset(offset) {
			return attr
		}
	}
	return nil
}

// IsInTagName checks if offset is within the tag name portion
func (e *HtmlElement) IsInTagName(offset int) bool {
	if e.Type != ElementOpenTag && e.Type != ElementCloseTag && e.Type != ElementSelfClosing {
		return false
	}
	// Tag name starts after '<' (or '</' for close tags)
	nameStart := e.StartOffset + 1
	if e.Type == ElementCloseTag {
		nameStart = e.StartOffset + 2
	}
	nameEnd := nameStart + len(e.TagName)
	return offset >= nameStart && offset < nameEnd
}
