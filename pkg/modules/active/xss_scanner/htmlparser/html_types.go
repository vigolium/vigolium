package htmlparser

import (
	"fmt"
	"strings"
)

// ParseMode định nghĩa các chế độ phân tích HTML.
// Tương đương với enum _9 trong Java.
type ParseMode int

const (
	// ParseModeNone không thực hiện phân tích đặc biệt.
	ParseModeNone ParseMode = iota
	// ParseModeHead chỉ phân tích đến hết thẻ </head>.
	ParseModeHead
	// ParseModeFull phân tích toàn bộ tài liệu.
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

// HTMLAttribute đại diện cho một thuộc tính của thẻ HTML.
// Tương đương với lớp apy / interface ffv trong Java.
type HTMLAttribute struct {
	Name       string    // cV()
	Value      string    // cY()
	NameStart  int       // cW()
	NameEnd    int       // cX()
	ValueStart int       // c0()
	ValueEnd   int       // cZ()
	QuoteType  QuoteType // 0: double ("), 1: single ('), 2: backtick (`), 3: none
}

// HTMLTagInfo chứa thông tin về một thẻ HTML.
// Tương đương với lớp apv / interface dr2 trong Java.
type HTMLTagInfo struct {
	Name       string // Tên thẻ, đã được chuyển thành chữ thường
	NameStart  int    // Vị trí bắt đầu của tên thẻ (sau '<' hoặc '</')
	NameEnd    int    // Vị trí kết thúc của tên thẻ
	Attributes []*HTMLAttribute
}

func (t *HTMLTagInfo) GetAttribute(name string) string {
	for _, attr := range t.Attributes {
		if strings.EqualFold(attr.Name, name) {
			return attr.Value
		}
	}
	return "" // Trả về chuỗi rỗng nếu không tìm thấy thuộc tính
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

// HTMLElementType định nghĩa loại của một phần tử HTML.
// Dựa trên trường 'e' của lớp apb trong Java.
type HTMLElementType byte

const (
	// OpenTag là một thẻ mở (ví dụ: <div>). Ánh xạ từ apb.e = 0.
	OpenTag HTMLElementType = 0
	// CloseTag là một thẻ đóng (ví dụ: </div>). Ánh xạ từ apb.e = 1.
	CloseTag HTMLElementType = 1
	// CommentOrDirective là một comment (<!-- ... -->) hoặc directive (<!...>). Ánh xạ từ apb.e = 2.
	CommentOrDirective HTMLElementType = 2
	// TextNode là một nút văn bản. Ánh xạ từ apb.e = 3.
	TextNode HTMLElementType = 3
	// SelfClosingTagOrPI là một thẻ tự đóng (ví dụ: <br/>, <img/>)
	// hoặc một processing instruction (ví dụ: <?xml ... ?>). Ánh xạ từ apb.e = 4.
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

// HTMLElement đại diện cho một phần tử trong cây HTML.
// Tương đương với lớp apb / interface ahe trong Java.
type HTMLElement struct {
	Type HTMLElementType // cU()
	// TagInfo chỉ có giá trị nếu Type là OpenTag, CloseTag, hoặc SelfClosingTagOrPI.
	TagInfo *HTMLTagInfo
	// Content chỉ có giá trị nếu Type là TextNode hoặc CommentOrDirective.
	// Đối với CommentOrDirective, Content chứa toàn bộ nội dung bao gồm cả <!-- và --> hoặc <! và >.
	// Đối với TextNode, Content là nội dung text đã được giải mã HTML entities (nếu cần).
	Content     string
	StartOffset int // cR()
	EndOffset   int // cV()
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

// IsAhe makes HTMLElement satisfy the Ahe interface (from hkk.go).
// func (h *HTMLElement) IsAhe() {} // No longer needed as Ahe interface is removed

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
