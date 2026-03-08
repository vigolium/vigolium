package xss_light_scanner

import (
	"testing"
)

func TestQuoteType_String(t *testing.T) {
	tests := []struct {
		name     string
		q        QuoteType
		expected string
	}{
		{"none", QuoteNone, "none"},
		{"double", QuoteDouble, "double"},
		{"single", QuoteSingle, "single"},
		{"backtick", QuoteBacktick, "backtick"},
		{"invalid", QuoteType(99), "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.q.String(); got != tt.expected {
				t.Errorf("QuoteType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHtmlElementType_String(t *testing.T) {
	tests := []struct {
		name     string
		typ      HtmlElementType
		expected string
	}{
		{"text", ElementText, "text"},
		{"open_tag", ElementOpenTag, "open_tag"},
		{"close_tag", ElementCloseTag, "close_tag"},
		{"self_closing", ElementSelfClosing, "self_closing"},
		{"comment", ElementComment, "comment"},
		{"directive", ElementDirective, "directive"},
		{"cdata", ElementCDATA, "cdata"},
		{"invalid", HtmlElementType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.typ.String(); got != tt.expected {
				t.Errorf("HtmlElementType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHtmlAttribute_ContainsOffset(t *testing.T) {
	attr := &HtmlAttribute{
		Name:       "class",
		Value:      "test-value",
		ValueStart: 10,
		ValueEnd:   20,
	}

	tests := []struct {
		name     string
		offset   int
		expected bool
	}{
		{"before_value", 5, false},
		{"at_value_start", 10, true},
		{"in_value_middle", 15, true},
		{"at_value_end_minus_1", 19, true},
		{"at_value_end", 20, false},
		{"after_value", 25, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := attr.ContainsOffset(tt.offset); got != tt.expected {
				t.Errorf("ContainsOffset(%d) = %v, want %v", tt.offset, got, tt.expected)
			}
		})
	}
}

func TestHtmlAttribute_ContainsNameOffset(t *testing.T) {
	attr := &HtmlAttribute{
		Name:      "onclick",
		NameStart: 5,
		NameEnd:   12,
	}

	tests := []struct {
		name     string
		offset   int
		expected bool
	}{
		{"before_name", 2, false},
		{"at_name_start", 5, true},
		{"in_name_middle", 8, true},
		{"at_name_end_minus_1", 11, true},
		{"at_name_end", 12, false},
		{"after_name", 15, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := attr.ContainsNameOffset(tt.offset); got != tt.expected {
				t.Errorf("ContainsNameOffset(%d) = %v, want %v", tt.offset, got, tt.expected)
			}
		})
	}
}

func TestHtmlElement_ContainsOffset(t *testing.T) {
	elem := &HtmlElement{
		Type:        ElementOpenTag,
		StartOffset: 0,
		EndOffset:   20,
		TagName:     "div",
	}

	tests := []struct {
		name     string
		offset   int
		expected bool
	}{
		{"at_start", 0, true},
		{"in_middle", 10, true},
		{"at_end_minus_1", 19, true},
		{"at_end", 20, false},
		{"after_end", 25, false},
		{"negative", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := elem.ContainsOffset(tt.offset); got != tt.expected {
				t.Errorf("ContainsOffset(%d) = %v, want %v", tt.offset, got, tt.expected)
			}
		})
	}
}

func TestHtmlElement_FindAttributeAtOffset(t *testing.T) {
	elem := &HtmlElement{
		Type:        ElementOpenTag,
		StartOffset: 0,
		EndOffset:   50,
		TagName:     "div",
		Attributes: []*HtmlAttribute{
			{Name: "id", NameStart: 5, NameEnd: 7, ValueStart: 9, ValueEnd: 15},
			{Name: "class", NameStart: 16, NameEnd: 21, ValueStart: 23, ValueEnd: 30},
		},
	}

	tests := []struct {
		name       string
		offset     int
		expectNil  bool
		expectName string
	}{
		{"in_id_name", 6, false, "id"},
		{"in_id_value", 10, false, "id"},
		{"in_class_name", 18, false, "class"},
		{"in_class_value", 25, false, "class"},
		{"between_attrs", 8, true, ""},
		{"before_all", 2, true, ""},
		{"after_all", 40, true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := elem.FindAttributeAtOffset(tt.offset)
			if tt.expectNil {
				if got != nil {
					t.Errorf("FindAttributeAtOffset(%d) = %v, want nil", tt.offset, got.Name)
				}
			} else {
				if got == nil {
					t.Errorf("FindAttributeAtOffset(%d) = nil, want %s", tt.offset, tt.expectName)
				} else if got.Name != tt.expectName {
					t.Errorf("FindAttributeAtOffset(%d).Name = %v, want %v", tt.offset, got.Name, tt.expectName)
				}
			}
		})
	}
}

func TestHtmlElement_IsInTagName(t *testing.T) {
	tests := []struct {
		name     string
		elem     *HtmlElement
		offset   int
		expected bool
	}{
		{
			name: "open_tag_in_name",
			elem: &HtmlElement{
				Type:        ElementOpenTag,
				StartOffset: 0,
				EndOffset:   10,
				TagName:     "div",
			},
			offset:   1, // '<' is at 0, 'd' at 1
			expected: true,
		},
		{
			name: "open_tag_after_name",
			elem: &HtmlElement{
				Type:        ElementOpenTag,
				StartOffset: 0,
				EndOffset:   10,
				TagName:     "div",
			},
			offset:   4, // after 'div'
			expected: false,
		},
		{
			name: "close_tag_in_name",
			elem: &HtmlElement{
				Type:        ElementCloseTag,
				StartOffset: 0,
				EndOffset:   6, // </div>
				TagName:     "div",
			},
			offset:   2, // '</' is at 0-1, 'd' at 2
			expected: true,
		},
		{
			name: "text_element",
			elem: &HtmlElement{
				Type:        ElementText,
				StartOffset: 0,
				EndOffset:   10,
			},
			offset:   5,
			expected: false,
		},
		{
			name: "self_closing_in_name",
			elem: &HtmlElement{
				Type:        ElementSelfClosing,
				StartOffset: 0,
				EndOffset:   6, // <br/>
				TagName:     "br",
			},
			offset:   1, // 'b' at 1
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.elem.IsInTagName(tt.offset); got != tt.expected {
				t.Errorf("IsInTagName(%d) = %v, want %v", tt.offset, got, tt.expected)
			}
		})
	}
}

func TestHtmlElement_FindAttributeAtOffset_Empty(t *testing.T) {
	elem := &HtmlElement{
		Type:        ElementOpenTag,
		StartOffset: 0,
		EndOffset:   10,
		TagName:     "div",
		Attributes:  nil,
	}

	if got := elem.FindAttributeAtOffset(5); got != nil {
		t.Errorf("FindAttributeAtOffset with nil Attributes = %v, want nil", got)
	}

	elem.Attributes = []*HtmlAttribute{}
	if got := elem.FindAttributeAtOffset(5); got != nil {
		t.Errorf("FindAttributeAtOffset with empty Attributes = %v, want nil", got)
	}
}
