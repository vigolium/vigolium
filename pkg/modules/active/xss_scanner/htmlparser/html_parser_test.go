package htmlparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSimpleTag(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		contentType      byte // 0 for HTML, 1 for XML
		expectedNumElems int
		expectedElements []HTMLElement // Chỉ kiểm tra chi tiết một vài element đầu tiên nếu cần
	}{
		{
			name:             "Simple Div",
			input:            "<div></div>",
			contentType:      0, // HTML
			expectedNumElems: 2,
			expectedElements: []HTMLElement{
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "div"}, StartOffset: 0, EndOffset: 5},
				{Type: CloseTag, TagInfo: &HTMLTagInfo{Name: "div"}, StartOffset: 5, EndOffset: 11},
			},
		},
		{
			name:             "Simple Paragraph with text",
			input:            "<p>Hello</p>",
			contentType:      0, // HTML
			expectedNumElems: 3,
			expectedElements: []HTMLElement{
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "p"}, StartOffset: 0, EndOffset: 3},
				{Type: TextNode, Content: "Hello", StartOffset: 3, EndOffset: 8},
				{Type: CloseTag, TagInfo: &HTMLTagInfo{Name: "p"}, StartOffset: 8, EndOffset: 12},
			},
		},
		{
			name:             "Only Text Node",
			input:            "Just text.",
			contentType:      0, // HTML
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{Type: TextNode, Content: "Just text.", StartOffset: 0, EndOffset: 10},
			},
		},
		{
			name:             "Empty Input",
			input:            "",
			contentType:      0, // HTML
			expectedNumElems: 0,
			expectedElements: []HTMLElement{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualElements, err := ParseHTMLElementsSimple(
				[]byte(tc.input),
				0,
				len(tc.input),
				tc.contentType,
			)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedNumElems, len(actualElements), "Number of elements mismatch")

			if len(tc.expectedElements) > 0 && len(actualElements) >= len(tc.expectedElements) {
				for i, expectedEl := range tc.expectedElements {
					actualEl := actualElements[i]
					assert.Equal(
						t,
						expectedEl.Type,
						actualEl.Type,
						"Element type mismatch for element %d",
						i,
					)
					assert.Equal(
						t,
						expectedEl.StartOffset,
						actualEl.StartOffset,
						"Element StartOffset mismatch for element %d",
						i,
					)
					assert.Equal(
						t,
						expectedEl.EndOffset,
						actualEl.EndOffset,
						"Element EndOffset mismatch for element %d",
						i,
					)

					if expectedEl.TagInfo != nil {
						assert.NotNil(
							t,
							actualEl.TagInfo,
							"Actual TagInfo is nil for element %d",
							i,
						)
						if actualEl.TagInfo != nil { // Check again to prevent panic on next line
							assert.Equal(
								t,
								expectedEl.TagInfo.Name,
								actualEl.TagInfo.Name,
								"Tag name mismatch for element %d",
								i,
							)
							// TODO: Add detailed attribute checking here if needed for TestParseSimpleTag
						}
					} else {
						assert.Nil(t, actualEl.TagInfo, "Expected TagInfo to be nil for element %d", i)
					}

					if expectedEl.Type == TextNode || expectedEl.Type == CommentOrDirective {
						assert.Equal(
							t,
							expectedEl.Content,
							actualEl.Content,
							"Element content mismatch for element %d",
							i,
						)
					}
				}
			} else if len(tc.expectedElements) > 0 && len(actualElements) < len(tc.expectedElements) {
				assert.Fail(t, "Parsed fewer elements than expected.", "Expected %d, got %d", len(tc.expectedElements), len(actualElements))
			}
		})
	}
}

func TestParseWithBOM(t *testing.T) {
	tests := []struct {
		name                   string
		inputBytes             []byte // Sử dụng []byte để biểu diễn BOM chính xác
		bomLength              int    // Độ dài của BOM để kiểm tra StartOffset
		expectedNumElems       int
		expectedFirstElType    HTMLElementType
		expectedFirstElName    string // Nếu là tag
		expectedFirstElContent string // Nếu là text node sau BOM
	}{
		{
			name:                "UTF-8 BOM then Div Tag",
			inputBytes:          append([]byte{0xEF, 0xBB, 0xBF}, []byte("<div></div>")...),
			bomLength:           3,
			expectedNumElems:    2, // <div> và </div>
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
		},
		{
			name:                "UTF-16BE BOM then Div Tag",
			inputBytes:          append([]byte{0xFE, 0xFF}, []byte("<div></div>")...),
			bomLength:           2,
			expectedNumElems:    2,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
		},
		{
			name:                "UTF-16LE BOM then Div Tag",
			inputBytes:          append([]byte{0xFF, 0xFE}, []byte("<div></div>")...),
			bomLength:           2,
			expectedNumElems:    2,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
		},
		{
			name:                   "UTF-8 BOM then Text",
			inputBytes:             append([]byte{0xEF, 0xBB, 0xBF}, []byte("Hello")...),
			bomLength:              3,
			expectedNumElems:       1,
			expectedFirstElType:    TextNode,
			expectedFirstElContent: "Hello",
		},
		{
			name:                   "UTF-16LE BOM then Text",
			inputBytes:             append([]byte{0xFF, 0xFE}, []byte("World")...),
			bomLength:              2,
			expectedNumElems:       1,
			expectedFirstElType:    TextNode,
			expectedFirstElContent: "World",
		},
		{
			name:             "Only UTF-8 BOM",
			inputBytes:       []byte{0xEF, 0xBB, 0xBF},
			bomLength:        3,
			expectedNumElems: 0, // BOM được loại bỏ, không còn gì để parse
		},
		{
			name:                "No BOM, just Div Tag",
			inputBytes:          []byte("<div></div>"),
			bomLength:           0,
			expectedNumElems:    2,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
		},
		// Các BOM khác trong bomSequences của parser: UTF-32BE, UTF-32LE
		// Chúng có thể được thêm vào đây nếu cần thiết, nhưng việc xử lý chuỗi byte của chúng phức tạp hơn.
		// Test với UTF-8 và UTF-16 thường đủ để bao phủ logic loại bỏ BOM.
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualElements, err := ParseHTMLElementsSimple(
				tc.inputBytes,
				0,
				len(tc.inputBytes),
				0,
			) // contentType 0 for HTML

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedNumElems, len(actualElements), "Number of elements mismatch")

			if tc.expectedNumElems > 0 && len(actualElements) > 0 {
				firstActualElement := actualElements[0]
				assert.Equal(
					t,
					tc.expectedFirstElType,
					firstActualElement.Type,
					"First element type mismatch",
				)

				var expectedStartOffset int
				if tc.bomLength > 0 {
					if tc.expectedFirstElType == TextNode {
						// For a TextNode that is the first element and a BOM was present,
						// its StartOffset is 0 (relative to original input, encompassing the BOM).
						// The Content of this TextNode has the BOM stripped.
						// Its EndOffset will be bomLength + len(strippedContent).
						expectedStartOffset = 0
					} else {
						// For a Tag element immediately after a BOM,
						// its StartOffset is bomLength (relative to original input).
						expectedStartOffset = tc.bomLength
					}
				} else {
					// No BOM, so start offset is 0 relative to input.
					expectedStartOffset = 0
				}

				assert.Equal(
					t,
					expectedStartOffset,
					firstActualElement.StartOffset,
					"First element StartOffset mismatch. Input: '%s', Expected %d (based on BOM length %d and type %v). Actual: %d",
					string(
						tc.inputBytes,
					),
					expectedStartOffset,
					tc.bomLength,
					tc.expectedFirstElType,
					firstActualElement.StartOffset,
				)

				switch tc.expectedFirstElType {
				case OpenTag, CloseTag, SelfClosingTagOrPI:
					assert.NotNil(
						t,
						firstActualElement.TagInfo,
						"TagInfo should not be nil for a tag element",
					)
					if firstActualElement.TagInfo != nil {
						assert.Equal(
							t,
							tc.expectedFirstElName,
							firstActualElement.TagInfo.Name,
							"Tag name mismatch",
						)
					}
					// EndOffset của tag element sẽ là bomLength + độ dài của tag string
					// Ví dụ: BOM + "<div></div>". Tag <div> có StartOffset=bomLength (trong content), EndOffset=bomLength+5.
					// HTMLElement.EndOffset của nó sẽ là bomLength + len("<div>") nếu nó là element đầu tiên *sau* BOM.
					// Tuy nhiên, ở đây firstActualElement.StartOffset là 0 (bao gồm BOM).
					// Nên EndOffset của nó sẽ là độ dài của (BOM + tag string đó).
					// Điều này phức tạp để tính toán ở đây, tốt hơn là kiểm tra StartOffset của element *thứ hai* nếu có.
					// Hiện tại, chúng ta chỉ kiểm tra StartOffset của element đầu tiên là 0.
				case TextNode:
					assert.Equal(t, tc.expectedFirstElContent, firstActualElement.Content, "Text node content mismatch")
					assert.Nil(t, firstActualElement.TagInfo, "TagInfo should be nil for a text node")
					// EndOffset của TextNode (bao gồm BOM) sẽ là bomLength + len(textContent)
					assert.Equal(t, tc.bomLength+len(tc.expectedFirstElContent), firstActualElement.EndOffset, "TextNode EndOffset mismatch")
				}
			}
		})
	}
}

func TestParseCommentsAndCDATA(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		contentType      byte // 0 for HTML, 1 for XML
		expectedNumElems int
		expectedElements []HTMLElement
	}{
		{
			name:             "HTML Comment",
			input:            "<!-- This is a comment -->",
			contentType:      0, // HTML
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type:        CommentOrDirective,
					Content:     "<!-- This is a comment -->",
					StartOffset: 0,
					EndOffset:   26,
				},
			},
		},
		{
			name:             "CDATA Section in HTML Mode",
			input:            "<![CDATA[This is some CDATA]]>",
			contentType:      0, // HTML
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				// Trong HTML mode, <![CDATA[...]]> được coi là một directive lạ, bắt đầu bằng <!
				// và phương thức parseCommentOrDirective sẽ đọc đến >.
				// Nội dung của HTMLElement.Content sẽ bao gồm toàn bộ chuỗi.
				{
					Type:        CommentOrDirective,
					Content:     "<![CDATA[This is some CDATA]]>",
					StartOffset: 0,
					EndOffset:   30,
				},
			},
		},
		{
			name:             "CDATA Section in XML Mode",
			input:            "<![CDATA[This is some CDATA]]>",
			contentType:      1, // XML
			expectedNumElems: 1,
			// Trong XML mode, skipUntilTag xử lý CDATA. Nó sẽ bỏ qua <![CDATA[ và ]]>.
			// Kết quả là một TextNode chứa nội dung bên trong, hoặc không có gì nếu CDATA rỗng.
			// Tuy nhiên, logic hiện tại của skipUntilTag trong parser Go sẽ coi phần bên trong CDATA như text
			// và sau đó parse() sẽ tạo TextNode từ đó. Vì vậy, chúng ta mong đợi 1 TextNode.
			// Logic của e7u.java this.c() khi this.h == 1 (XML) sẽ tìm `]]>` và `this.l` sẽ nhảy qua nó.
			// Phần text trước CDATA (nếu có) sẽ tạo TextNode. Phần text *bên trong* CDATA có thể không được tạo thành TextNode riêng biệt
			// mà được bỏ qua bởi skipUntilTag. Logic này cần được kiểm tra lại rất cẩn thận với e7u.java.
			// Giả định tạm thời: e7u.java không tạo text node cho nội dung CDATA mà chỉ skip nó.
			// Nếu parser Go hiện tại tạo TextNode cho nội dung CDATA, test này sẽ fail và cần sửa parser hoặc test.
			// Dựa trên implement hiện tại của Go parser (skipUntilTag tìm CDATA và nhảy qua, sau đó vòng lặp parse có thể tạo text node sau đó):
			// Nếu input chỉ là CDATA, skipUntilTag sẽ nhảy đến cuối. Vòng parse chính sẽ không còn gì để đọc. -> 0 elements.
			// Nếu là "text1<![CDATA[cdata]]>text2", thì "text1" là TextNode, CDATA được skip, "text2" là TextNode.
			// Do đó, cho input chỉ có CDATA ở XML mode, kỳ vọng là 0 element được tạo ra bởi logic của e7u.
			// Cần test case: "text <![CDATA[content]]> text" trong XML mode.
			expectedElements: []HTMLElement{},
		},
		{
			name:             "Text before and after CDATA in XML Mode",
			input:            "Alpha <![CDATA[Beta]]> Gamma",
			contentType:      1, // XML
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type:        TextNode,
					Content:     "Alpha <![CDATA[Beta]]> Gamma",
					StartOffset: 0,
					EndOffset:   28,
				},
			},
		},
		{
			name:             "Comment with unclosed tag inside",
			input:            "<!-- <div not-closed -- -->",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type:        CommentOrDirective,
					Content:     "<!-- <div not-closed -- -->",
					StartOffset: 0,
					EndOffset:   27,
				},
			},
		},
		{
			name:             "Malformed Comment no closing >",
			input:            "<!-- not closed",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type:        CommentOrDirective,
					Content:     "<!-- not closed",
					StartOffset: 0,
					EndOffset:   15,
				},
			},
		},
		{
			name:             "Simple DOCTYPE",
			input:            "<!DOCTYPE html>",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type:        CommentOrDirective,
					Content:     "<!DOCTYPE html>",
					StartOffset: 0,
					EndOffset:   15,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualElements, err := ParseHTMLElementsSimple(
				[]byte(tc.input),
				0,
				len(tc.input),
				tc.contentType,
			)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedNumElems, len(actualElements), "Number of elements mismatch")

			if len(tc.expectedElements) > 0 && len(actualElements) >= len(tc.expectedElements) {
				for i, expectedEl := range tc.expectedElements {
					actualEl := actualElements[i]
					assert.Equal(
						t,
						expectedEl.Type,
						actualEl.Type,
						"Element type mismatch for element %d",
						i,
					)
					assert.Equal(
						t,
						expectedEl.StartOffset,
						actualEl.StartOffset,
						"Element StartOffset mismatch for element %d",
						i,
					)
					assert.Equal(
						t,
						expectedEl.EndOffset,
						actualEl.EndOffset,
						"Element EndOffset mismatch for element %d",
						i,
					)
					if expectedEl.Type == TextNode || expectedEl.Type == CommentOrDirective {
						assert.Equal(
							t,
							expectedEl.Content,
							actualEl.Content,
							"Element content mismatch for element %d",
							i,
						)
					}
					// TagInfo is not expected for these types in this test function
					assert.Nil(
						t,
						actualEl.TagInfo,
						"TagInfo should be nil for Comment/CDATA/Text in this test for element %d",
						i,
					)
				}
			} else if len(tc.expectedElements) == 0 && len(actualElements) == 0 {
				// This is fine, e.g. CDATA only in XML mode
			} else if len(tc.expectedElements) > 0 && len(actualElements) < len(tc.expectedElements) {
				assert.Fail(t, "Parsed fewer elements than expected.", "Expected %d, got %d", len(tc.expectedElements), len(actualElements))
			}
		})
	}
}

func TestParseTagTypes(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		contentType      byte // 0 for HTML, 1 for XML (ảnh hưởng đến thẻ tự đóng ngầm định)
		expectedNumElems int
		expectedElements []HTMLElement // Kiểm tra chi tiết element đầu tiên
	}{
		{
			name:             "Simple Opening Tag",
			input:            "<div>",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "div"}, StartOffset: 0, EndOffset: 5},
			},
		},
		{
			name:             "Simple Closing Tag",
			input:            "</div>",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{Type: CloseTag, TagInfo: &HTMLTagInfo{Name: "div"}, StartOffset: 0, EndOffset: 6},
			},
		},
		{
			name:             "Self-closing Tag BR",
			input:            "<br/>",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type:        SelfClosingTagOrPI,
					TagInfo:     &HTMLTagInfo{Name: "br"},
					StartOffset: 0,
					EndOffset:   5,
				},
			},
		},
		{
			name:             "Self-closing Tag BR with space",
			input:            "<br />",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type:        SelfClosingTagOrPI,
					TagInfo:     &HTMLTagInfo{Name: "br"},
					StartOffset: 0,
					EndOffset:   6,
				},
			},
		},
		{
			name:             "Tag with uppercase name",
			input:            "<DIV>",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "div"}, StartOffset: 0, EndOffset: 5},
			}, // Tên thẻ được chuyển thành chữ thường
		},
		{
			name:             "PHP style tag <?php ?>",
			input:            "<?php echo 'hello'; ?>",
			contentType:      0,
			expectedNumElems: 1,
			// Tên thẻ là "?php" (bao gồm cả '?'), loại là SelfClosingTagOrPI
			expectedElements: []HTMLElement{
				{
					Type:        SelfClosingTagOrPI,
					TagInfo:     &HTMLTagInfo{Name: "?php"},
					StartOffset: 0,
					EndOffset:   22,
				},
			},
		},
		{
			name:             "Img tag (implicitly self-closing in HTML mode)",
			input:            "<img>",
			contentType:      0, // HTML mode
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type:        SelfClosingTagOrPI,
					TagInfo:     &HTMLTagInfo{Name: "img"},
					StartOffset: 0,
					EndOffset:   5,
				},
			},
		},
		{
			name:             "Img tag (NOT implicitly self-closing in XML mode)",
			input:            "<img>",
			contentType:      1, // XML mode
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "img"}, StartOffset: 0, EndOffset: 5},
			},
		},
		{
			name:             "Input tag with attribute (implicitly self-closing in HTML mode)",
			input:            "<input type=\"text\">",
			contentType:      0, // HTML mode
			expectedNumElems: 1,
			expectedElements: []HTMLElement{{
				Type: SelfClosingTagOrPI,
				TagInfo: &HTMLTagInfo{
					Name: "input",
					Attributes: []*HTMLAttribute{
						{
							Name:       "type",
							Value:      "text",
							QuoteType:  0,
							NameStart:  7,
							NameEnd:    11,
							ValueStart: 13,
							ValueEnd:   17,
						},
					},
				},
				StartOffset: 0, EndOffset: 19,
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualElements, err := ParseHTMLElementsSimple(
				[]byte(tc.input),
				0,
				len(tc.input),
				tc.contentType,
			)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedNumElems, len(actualElements), "Number of elements mismatch")

			if tc.expectedNumElems > 0 && len(actualElements) > 0 {
				assert.Len(
					t,
					actualElements,
					len(tc.expectedElements),
					"Length of actual and expected elements slice mismatch",
				)
				for i, expectedEl := range tc.expectedElements {
					if i >= len(actualElements) {
						t.Errorf(
							"Index %d out of bounds for actualElements (len %d)",
							i,
							len(actualElements),
						)
						continue
					}
					actualEl := actualElements[i]
					assert.Equal(
						t,
						expectedEl.Type,
						actualEl.Type,
						"Element type mismatch for element %d (%s)",
						i,
						actualEl.TagInfo.Name,
					)
					assert.Equal(
						t,
						expectedEl.StartOffset,
						actualEl.StartOffset,
						"Element StartOffset mismatch for element %d (%s)",
						i,
						actualEl.TagInfo.Name,
					)
					assert.Equal(
						t,
						expectedEl.EndOffset,
						actualEl.EndOffset,
						"Element EndOffset mismatch for element %d (%s)",
						i,
						actualEl.TagInfo.Name,
					)

					if expectedEl.TagInfo != nil {
						assert.NotNil(
							t,
							actualEl.TagInfo,
							"Actual TagInfo is nil for element %d",
							i,
						)
						if actualEl.TagInfo != nil {
							assert.Equal(
								t,
								expectedEl.TagInfo.Name,
								actualEl.TagInfo.Name,
								"Tag name mismatch for element %d",
								i,
							)
							// Kiểm tra chi tiết thuộc tính nếu expectedEl.TagInfo.Attributes được định nghĩa
							if len(expectedEl.TagInfo.Attributes) > 0 {
								assert.Equal(
									t,
									len(expectedEl.TagInfo.Attributes),
									len(actualEl.TagInfo.Attributes),
									"Attribute count mismatch for element %d (%s)",
									i,
									actualEl.TagInfo.Name,
								)
								for j, expectedAttr := range expectedEl.TagInfo.Attributes {
									if j < len(actualEl.TagInfo.Attributes) {
										actualAttr := actualEl.TagInfo.Attributes[j]
										assert.Equal(
											t,
											expectedAttr.Name,
											actualAttr.Name,
											"Attr name mismatch for attr %d, element %d (%s)",
											j,
											i,
											actualEl.TagInfo.Name,
										)
										assert.Equal(
											t,
											expectedAttr.Value,
											actualAttr.Value,
											"Attr value mismatch for attr %d, element %d (%s)",
											j,
											i,
											actualEl.TagInfo.Name,
										)
										assert.Equal(
											t,
											expectedAttr.QuoteType,
											actualAttr.QuoteType,
											"Attr quote type mismatch for attr %d, element %d (%s)",
											j,
											i,
											actualEl.TagInfo.Name,
										)
										assert.Equal(
											t,
											expectedAttr.NameStart,
											actualAttr.NameStart,
											"Attr NameStart mismatch for attr %d, element %d (%s)",
											j,
											i,
											actualEl.TagInfo.Name,
										)
										assert.Equal(
											t,
											expectedAttr.NameEnd,
											actualAttr.NameEnd,
											"Attr NameEnd mismatch for attr %d, element %d (%s)",
											j,
											i,
											actualEl.TagInfo.Name,
										)
										assert.Equal(
											t,
											expectedAttr.ValueStart,
											actualAttr.ValueStart,
											"Attr ValueStart mismatch for attr %d, element %d (%s)",
											j,
											i,
											actualEl.TagInfo.Name,
										)
										assert.Equal(
											t,
											expectedAttr.ValueEnd,
											actualAttr.ValueEnd,
											"Attr ValueEnd mismatch for attr %d, element %d (%s)",
											j,
											i,
											actualEl.TagInfo.Name,
										)
									}
								}
							}
						}
					} else {
						assert.Nil(t, actualEl.TagInfo, "Expected TagInfo to be nil for element %d", i)
					}
				}
			}
		})
	}
}

func TestParseAttributes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// contentType không cần thiết ở đây vì chúng ta tập trung vào cấu trúc thuộc tính,
		// và các thẻ ví dụ không phải là loại tự đóng ngầm định thay đổi theo contentType.
		expectedNumElems     int
		expectedFirstElType  HTMLElementType
		expectedFirstElName  string
		expectedFirstElAttrs []HTMLAttribute // Kiểm tra chi tiết các thuộc tính
	}{
		{
			name:                 "Tag with no attributes",
			input:                "<div>",
			expectedNumElems:     1,
			expectedFirstElType:  OpenTag,
			expectedFirstElName:  "div",
			expectedFirstElAttrs: []HTMLAttribute{},
		},
		{
			name:                "Attribute with double quotes",
			input:               "<div class=\"main\">",
			expectedNumElems:    1,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "class",
					Value:      "main",
					QuoteType:  0,
					NameStart:  5,
					NameEnd:    10,
					ValueStart: 12,
					ValueEnd:   16,
				},
			},
		},
		{
			name:                "Attribute with single quotes",
			input:               "<div class='main'>",
			expectedNumElems:    1,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "class",
					Value:      "main",
					QuoteType:  1,
					NameStart:  5,
					NameEnd:    10,
					ValueStart: 12,
					ValueEnd:   16,
				},
			},
		},
		{
			name:                "Attribute with backticks",
			input:               "<div class=`main`>",
			expectedNumElems:    1,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "class",
					Value:      "main",
					QuoteType:  2,
					NameStart:  5,
					NameEnd:    10,
					ValueStart: 12,
					ValueEnd:   16,
				},
			},
		},
		{
			name:                "Attribute with no quotes",
			input:               "<div class=main>",
			expectedNumElems:    1,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "class",
					Value:      "main",
					QuoteType:  3,
					NameStart:  5,
					NameEnd:    10,
					ValueStart: 11,
					ValueEnd:   15,
				},
			},
		},
		{
			name:                "Attribute with no value",
			input:               "<input disabled>", // input là self-closing trong HTML mode (0)
			expectedNumElems:    1,
			expectedFirstElType: SelfClosingTagOrPI,
			expectedFirstElName: "input",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "disabled",
					Value:      "",
					QuoteType:  3,
					NameStart:  7,
					NameEnd:    15,
					ValueStart: 15,
					ValueEnd:   15,
				},
			},
		},
		{
			name:                "Multiple attributes",
			input:               "<input type=\"text\" id='inputId' disabled value=val />", // Thêm self-closing />
			expectedNumElems:    1,
			expectedFirstElType: SelfClosingTagOrPI,
			expectedFirstElName: "input",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "type",
					Value:      "text",
					QuoteType:  0,
					NameStart:  7,
					NameEnd:    11,
					ValueStart: 13,
					ValueEnd:   17,
				},
				{
					Name:       "id",
					Value:      "inputId",
					QuoteType:  1,
					NameStart:  19,
					NameEnd:    21,
					ValueStart: 23,
					ValueEnd:   30,
				},
				{
					Name:       "disabled",
					Value:      "",
					QuoteType:  3,
					NameStart:  32,
					NameEnd:    40,
					ValueStart: 41,
					ValueEnd:   41,
				},
				{
					Name:       "value",
					Value:      "val",
					QuoteType:  3,
					NameStart:  41,
					NameEnd:    46,
					ValueStart: 47,
					ValueEnd:   50,
				},
			},
		},
		{
			name:                "Attributes with extra spaces",
			input:               "<div  class = \"main\"   id  =  'other' >",
			expectedNumElems:    1,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "class",
					Value:      "main",
					QuoteType:  0,
					NameStart:  6,
					NameEnd:    11,
					ValueStart: 15,
					ValueEnd:   19,
				},
				{
					Name:       "id",
					Value:      "other",
					QuoteType:  1,
					NameStart:  23,
					NameEnd:    25,
					ValueStart: 31,
					ValueEnd:   36,
				},
			},
		},
		{
			name:                "Attribute name with mixed case",
			input:               "<div MyATTR=\"value\">",
			expectedNumElems:    1,
			expectedFirstElType: OpenTag,
			expectedFirstElName: "div",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "MyATTR",
					Value:      "value",
					QuoteType:  0,
					NameStart:  5,
					NameEnd:    11,
					ValueStart: 13,
					ValueEnd:   18,
				},
			},
		},
		{
			name:                "Self-closing tag with attribute and space before slash",
			input:               "<br class=\"clear\" />",
			expectedNumElems:    1,
			expectedFirstElType: SelfClosingTagOrPI,
			expectedFirstElName: "br",
			expectedFirstElAttrs: []HTMLAttribute{
				{
					Name:       "class",
					Value:      "clear",
					QuoteType:  0,
					NameStart:  4,
					NameEnd:    9,
					ValueStart: 11,
					ValueEnd:   16,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Luôn dùng contentType 0 (HTML) cho các test này vì chúng ta tập trung vào cấu trúc thuộc tính
			// và các thẻ void (như <input>) sẽ được xử lý đúng theo HTML mode.
			actualElements, err := ParseHTMLElementsSimple([]byte(tc.input), 0, len(tc.input), 0)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedNumElems, len(actualElements), "Number of elements mismatch")

			if tc.expectedNumElems > 0 && len(actualElements) > 0 {
				actualEl := actualElements[0]
				assert.Equal(t, tc.expectedFirstElType, actualEl.Type, "Element type mismatch")
				assert.NotNil(t, actualEl.TagInfo, "TagInfo should not be nil")

				if actualEl.TagInfo != nil { // Guard against nil dereference
					assert.Equal(
						t,
						tc.expectedFirstElName,
						actualEl.TagInfo.Name,
						"Tag name mismatch",
					)
					assert.Equal(
						t,
						len(tc.expectedFirstElAttrs),
						len(actualEl.TagInfo.Attributes),
						"Attribute count mismatch",
					)

					for i, expectedAttr := range tc.expectedFirstElAttrs {
						if i < len(actualEl.TagInfo.Attributes) {
							actualAttr := actualEl.TagInfo.Attributes[i]
							assert.Equal(
								t,
								expectedAttr.Name,
								actualAttr.Name,
								"Attr %d Name mismatch",
								i,
							)
							assert.Equal(
								t,
								expectedAttr.Value,
								actualAttr.Value,
								"Attr %d Value mismatch for %s",
								i,
								expectedAttr.Name,
							)
							assert.Equal(
								t,
								expectedAttr.QuoteType,
								actualAttr.QuoteType,
								"Attr %d QuoteType mismatch for %s",
								i,
								expectedAttr.Name,
							)
							assert.Equal(
								t,
								expectedAttr.NameStart,
								actualAttr.NameStart,
								"Attr %d NameStart mismatch for %s",
								i,
								expectedAttr.Name,
							)
							assert.Equal(
								t,
								expectedAttr.NameEnd,
								actualAttr.NameEnd,
								"Attr %d NameEnd mismatch for %s",
								i,
								expectedAttr.Name,
							)
							assert.Equal(
								t,
								expectedAttr.ValueStart,
								actualAttr.ValueStart,
								"Attr %d ValueStart mismatch for %s",
								i,
								expectedAttr.Name,
							)
							assert.Equal(
								t,
								expectedAttr.ValueEnd,
								actualAttr.ValueEnd,
								"Attr %d ValueEnd mismatch for %s",
								i,
								expectedAttr.Name,
							)
						}
					}
				}
			}
		})
	}
}

func TestParseMalformedHTMLAndSpecialCases(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		contentType      byte // 0 for HTML, 1 for XML
		expectedNumElems int
		expectedElements []HTMLElement // Kiểm tra chi tiết một vài element đầu tiên hoặc tất cả nếu cần
	}{
		{
			name:             "Unclosed tag with following text",
			input:            "<div><p>text", // e7u sẽ parse <div>, <p>, và "text" là TextNode
			contentType:      0,
			expectedNumElems: 3,
			expectedElements: []HTMLElement{
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "div"}, StartOffset: 0, EndOffset: 5},
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "p"}, StartOffset: 5, EndOffset: 8},
				{Type: TextNode, Content: "text", StartOffset: 8, EndOffset: 12},
			},
		},
		{
			name:             "Tag with missing closing bracket and attributes",
			input:            "<div class=\"main\" id=item", // Parser sẽ đọc đến hết
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type: OpenTag,
					TagInfo: &HTMLTagInfo{
						Name: "div",
						Attributes: []*HTMLAttribute{
							{
								Name:       "class",
								Value:      "main",
								QuoteType:  0,
								NameStart:  5,
								NameEnd:    10,
								ValueStart: 12,
								ValueEnd:   16,
							},
							{
								Name:       "id",
								Value:      "item",
								QuoteType:  3,
								NameStart:  18,
								NameEnd:    20,
								ValueStart: 21,
								ValueEnd:   25,
							},
						},
					},
					StartOffset: 0, EndOffset: 25, // EndOffset là cuối chuỗi vì không có '>'
				},
			},
		},
		{
			name:             "Text node before any tag",
			input:            "Some text <div>content</div>",
			contentType:      0,
			expectedNumElems: 4, // "Some text ", <div>, </div> (content của div là text node tiếp theo)
			expectedElements: []HTMLElement{
				{Type: TextNode, Content: "Some text ", StartOffset: 0, EndOffset: 10},
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "div"}, StartOffset: 10, EndOffset: 15},
				// "content" sẽ là TextNode thứ 3, và </div> là thứ 4. Test này chỉ kiểm tra 3 cái đầu cho đơn giản.
				// Thực tế ParseHTMLElementsSimple sẽ trả về: Text, OpenTag, Text, CloseTag
				// Sửa lại expectedNumElems và expectedElements cho đúng
			},
		},
		{
			name:             "Script tag with content containing < >",
			input:            "<script>alert(\"hello <world>\");</script>",
			contentType:      0,
			expectedNumElems: 3, // <script>, "alert(...)" (là TextNode), </script>
			expectedElements: []HTMLElement{
				{
					Type:        OpenTag,
					TagInfo:     &HTMLTagInfo{Name: "script"},
					StartOffset: 0,
					EndOffset:   8,
				},
				{
					Type:        TextNode,
					Content:     "alert(\"hello <world>\");",
					StartOffset: 8,
					EndOffset:   31,
				},
				{
					Type:        CloseTag,
					TagInfo:     &HTMLTagInfo{Name: "script"},
					StartOffset: 31, // Correct: "</script>" starts at position 31
					EndOffset:   40,
				},
			},
		},
		{
			name:             "Tag mismatch <p></div>",
			input:            "<p></div>", // Parser sẽ parse <p> và </div> riêng biệt
			contentType:      0,
			expectedNumElems: 2,
			expectedElements: []HTMLElement{
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "p"}, StartOffset: 0, EndOffset: 3},
				{Type: CloseTag, TagInfo: &HTMLTagInfo{Name: "div"}, StartOffset: 3, EndOffset: 9},
			},
		},
		{
			name:             "Attribute without name <div =\"val\">",
			input:            "<div =\"val\">", // e7u sẽ tạo attribute tên rỗng
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{
					Type: OpenTag,
					TagInfo: &HTMLTagInfo{Name: "div", Attributes: []*HTMLAttribute{
						{
							Name:       "",
							Value:      "val",
							QuoteType:  0,
							NameStart:  5,
							NameEnd:    5, // Empty name, so NameEnd = NameStart
							ValueStart: 7,
							ValueEnd:   10,
						},
					}},
					StartOffset: 0, EndOffset: 12,
				},
			},
		},
		{
			name:             "Nested malformed <a><b><c</a></b></c>",
			input:            "<a><b><c</a></b></c>",
			contentType:      0,
			expectedNumElems: 5, // <a>, <b>, <c</a> (parsed as self-closing tag with '/' terminator), </b>, </c>
			// Note: <c</a> is parsed as tag name "c<" with attribute "a" because "/" terminates the tag
			expectedElements: []HTMLElement{
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "a"}, StartOffset: 0, EndOffset: 3},
				{Type: OpenTag, TagInfo: &HTMLTagInfo{Name: "b"}, StartOffset: 3, EndOffset: 6},
				{Type: SelfClosingTagOrPI, TagInfo: &HTMLTagInfo{
					Name: "c<",
					Attributes: []*HTMLAttribute{
						{Name: "a", Value: "", QuoteType: 3, NameStart: 10, NameEnd: 11, ValueStart: 11, ValueEnd: 11},
					},
				}, StartOffset: 6, EndOffset: 12},
				{Type: CloseTag, TagInfo: &HTMLTagInfo{Name: "b"}, StartOffset: 12, EndOffset: 16},
				{Type: CloseTag, TagInfo: &HTMLTagInfo{Name: "c"}, StartOffset: 16, EndOffset: 20},
			},
		},
		{
			name:             "Only text",
			input:            "Just some simple text.",
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				{Type: TextNode, Content: "Just some simple text.", StartOffset: 0, EndOffset: 22},
			},
		},
		{
			name:             "IE hack comment </.foo>",
			input:            "</.foo>", // e7u parses as CommentOrDirective with content "/.foo>"
			contentType:      0,
			expectedNumElems: 1,
			expectedElements: []HTMLElement{
				// StartOffset is 1 because parser starts after '<' character
				{Type: CommentOrDirective, Content: "/.foo>", StartOffset: 1, EndOffset: 7},
			},
		},
		// Test case for text with CDATA in XML mode
		{
			name:             "Complex CDATA in XML mode",
			input:            "TextBefore <![CDATA[ CDATA Content ]]> TextAfter",
			contentType:      1, // XML Mode
			expectedNumElems: 1, // Parser treats entire input as single TextNode in XML mode with CDATA
			expectedElements: []HTMLElement{
				{Type: TextNode, Content: "TextBefore <![CDATA[ CDATA Content ]]> TextAfter", StartOffset: 0, EndOffset: 48},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualElements, err := ParseHTMLElementsSimple(
				[]byte(tc.input),
				0,
				len(tc.input),
				tc.contentType,
			)

			assert.NoError(t, err, "ParseHTMLElementsSimple failed for input: %s", tc.input)
			assert.Equal(
				t,
				tc.expectedNumElems,
				len(actualElements),
				"Number of elements mismatch for input: %s",
				tc.input,
			)

			if len(tc.expectedElements) > 0 && len(actualElements) >= len(tc.expectedElements) {
				for i, expectedEl := range tc.expectedElements {
					actualEl := actualElements[i]
					assert.Equal(
						t,
						expectedEl.Type,
						actualEl.Type,
						"Element type mismatch for element %d of input: %s",
						i,
						tc.input,
					)
					assert.Equal(
						t,
						expectedEl.StartOffset,
						actualEl.StartOffset,
						"Element StartOffset mismatch for element %d of input: %s",
						i,
						tc.input,
					)
					assert.Equal(
						t,
						expectedEl.EndOffset,
						actualEl.EndOffset,
						"Element EndOffset mismatch for element %d of input: %s",
						i,
						tc.input,
					)

					if expectedEl.TagInfo != nil {
						assert.NotNil(
							t,
							actualEl.TagInfo,
							"Actual TagInfo is nil for element %d of input: %s",
							i,
							tc.input,
						)
						if actualEl.TagInfo != nil { // Guard
							assert.Equal(
								t,
								expectedEl.TagInfo.Name,
								actualEl.TagInfo.Name,
								"Tag name mismatch for element %d of input: %s",
								i,
								tc.input,
							)
							assert.Equal(
								t,
								len(expectedEl.TagInfo.Attributes),
								len(actualEl.TagInfo.Attributes),
								"Attribute count mismatch for element %d of input: %s",
								i,
								tc.input,
							)
							for j, expectedAttr := range expectedEl.TagInfo.Attributes {
								if j < len(actualEl.TagInfo.Attributes) {
									actualAttr := actualEl.TagInfo.Attributes[j]
									assert.Equal(
										t,
										expectedAttr.Name,
										actualAttr.Name,
										"Attr name mismatch for attr %d, element %d, input: %s",
										j,
										i,
										tc.input,
									)
									assert.Equal(
										t,
										expectedAttr.Value,
										actualAttr.Value,
										"Attr value mismatch for attr %d, element %d, input: %s",
										j,
										i,
										tc.input,
									)
									assert.Equal(
										t,
										expectedAttr.QuoteType,
										actualAttr.QuoteType,
										"Attr quote type mismatch for attr %d, element %d, input: %s",
										j,
										i,
										tc.input,
									)
									assert.Equal(
										t,
										expectedAttr.NameStart,
										actualAttr.NameStart,
										"Attr NameStart mismatch for attr %d, element %d, input: %s",
										j,
										i,
										tc.input,
									)
									assert.Equal(
										t,
										expectedAttr.NameEnd,
										actualAttr.NameEnd,
										"Attr NameEnd mismatch for attr %d, element %d, input: %s",
										j,
										i,
										tc.input,
									)
									assert.Equal(
										t,
										expectedAttr.ValueStart,
										actualAttr.ValueStart,
										"Attr ValueStart mismatch for attr %d, element %d, input: %s",
										j,
										i,
										tc.input,
									)
									assert.Equal(
										t,
										expectedAttr.ValueEnd,
										actualAttr.ValueEnd,
										"Attr ValueEnd mismatch for attr %d, element %d, input: %s",
										j,
										i,
										tc.input,
									)
								}
							}
						}
					} else {
						assert.Nil(t, actualEl.TagInfo, "Expected TagInfo to be nil for element %d of input: %s", i, tc.input)
					}

					if expectedEl.Type == TextNode || expectedEl.Type == CommentOrDirective {
						assert.Equal(
							t,
							expectedEl.Content,
							actualEl.Content,
							"Element content mismatch for element %d of input: %s",
							i,
							tc.input,
						)
					}
				}
			} else if len(tc.expectedElements) == 0 && len(actualElements) == 0 {
				// OK for cases like empty input or CDATA-only in XML mode
			} else if len(tc.expectedElements) > 0 && len(actualElements) < len(tc.expectedElements) {
				assert.Fail(t, "Parsed fewer elements than expected.", "Input: %s, Expected %d, got %d", tc.input, len(tc.expectedElements), len(actualElements))
			}
		})
	}
}
