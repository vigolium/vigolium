package htmlparser

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)


var (
	// endComment = []byte{'-', '-', '>'} // -->
	endComment = []byte{'-', '-', '>'}
	// cdataStart = []byte{'<', '!', '[', 'C', 'D', 'A', 'T', 'A', '['} // <![CDATA[
	cdataStart = []byte{'<', '!', '[', 'C', 'D', 'A', 'T', 'A', '['}
	// cdataEnd = []byte{']', ']', '>'} // ]]>
	cdataEnd = []byte{']', ']', '>'}
	// scriptTagEnd is used to detect </script>
	scriptTagEnd = []byte{'/', 's', 'c', 'r', 'i', 'p', 't'}

	// bomSequences lists BOM byte sequences to strip from the beginning of input.
	bomSequences = [][]byte{
		{0, 0, 0xFE, 0xFF}, // UTF-32BE BOM
		{0xFF, 0xFE, 0, 0}, // UTF-32LE BOM
		{0xEF, 0xBB, 0xBF}, // UTF-8 BOM
		{0xFE, 0xFF},       // UTF-16BE BOM
		{0xFF, 0xFE},       // UTF-16LE BOM
	}
)

// HTMLParser is the main struct that performs HTML parsing.
type HTMLParser struct {
	startIdx     int            // start offset in the original data
	endIdx       int            // end offset in the original data
	data         *utils.ByteSequence     // input data
	contentType  byte           // 0 for HTML, 1 for XML
	parseMode    ParseMode
	elements     []*HTMLElement // parsed elements
	currentIndex int            // current parse position
	inScript     bool           // true when inside a <script> tag
}

// NewHTMLParser creates a new HTMLParser instance.
func NewHTMLParser(
	data *utils.ByteSequence,
	startIdx, endIdx int,
	contentType byte,
	mode ParseMode,
) *HTMLParser {
	if startIdx < 0 {
		startIdx = 0
	}
	if endIdx > data.Length() {
		endIdx = data.Length()
	}

	return &HTMLParser{
		startIdx:     startIdx,
		endIdx:       endIdx,
		data:         data,
		contentType:  contentType,
		parseMode:    mode,
		elements:     make([]*HTMLElement, 0),
		currentIndex: startIdx,
		inScript:     false,
	}
}

// shouldStopForHTMLHead checks whether parsing should stop in HEAD mode.
func shouldStopForHTMLHead(elements []*HTMLElement, contentType byte, parseMode ParseMode) bool {
	if contentType != 0 /* HTML */ || parseMode != ParseModeHead {
		return false
	}
	if len(elements) == 0 {
		return false
	}
	lastElement := elements[len(elements)-1]
	isClosingHeadTag := lastElement.Type == CloseTag &&
		lastElement.TagInfo != nil &&
		strings.ToLower(lastElement.TagInfo.Name) == "head"
	return isClosingHeadTag
}

// parse is the main method that performs HTML/XML parsing.
func (p *HTMLParser) parse(var1 func() bool) (err error) {
	defer func() {
		if var25 := recover(); var25 != nil {
			var2, ok := var25.(error)
			if !ok {
				var2 = fmt.Errorf("%v", var25)
			}

				err = fmt.Errorf(
				"UNEXPECTED_PARSER_ERROR: %v - Context: %s",
				var2,
				p.getContextForError(),
			)

			zap.L().Debug("HTML Parser Error",
				zap.Error(var2),
				zap.String("context", p.getContextForError()))
		}
	}()

	p.currentIndex = p.startIdx

	for {
		if p.currentIndex >= p.endIdx ||
			shouldStopForHTMLHead(p.elements, p.contentType, p.parseMode) {
			zap.L().Debug("HTML parser reached end",
				zap.Int("startIdx", p.startIdx),
				zap.Int("endIdx", p.endIdx),
				zap.Int("currentIndex", p.currentIndex))
			return nil
		}

		if var1 != nil && var1() {
			return nil
		}

		var2 := p.currentIndex

		p.skipUntilTag()

		if p.currentIndex > var2 {
			var3, _ := p.data.SubSequence(var2, p.currentIndex)

			if len(p.elements) == 0 {
				var3 = p.removeInitialBom(var2, var3)
			}

			if var3.Length() > 0 {
				p.elements = append(
					p.elements,
					NewHTMLElement(
						var2,
						p.currentIndex,
						TextNode,
						nil,
						var3.GetString(),
					),
				)
			}
		}

		if p.currentIndex < p.endIdx-1 {
			if p.data.GetByte(p.currentIndex+1) == 33 {
				p.parseCommentOrDirective()
				continue
			}

			var20 := p.currentIndex

			var4 := OpenTag

			p.currentIndex++

			if p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) == 47 {
				if p.currentIndex+1 < p.endIdx && p.data.GetByte(p.currentIndex+1) == 46 {
					p.parseCommentOrDirective()
					continue
				}

				var4 = CloseTag

				p.currentIndex++
			}

			var2 = p.currentIndex

			var5 := p.parseTagName()

			if p.currentIndex < p.endIdx {
				var7 := p.currentIndex

				if p.data.GetByte(var2) == 63 {
					var4 = SelfClosingTagOrPI
				}

				var8 := make([]*HTMLAttribute, 0)

				if var4 == 1 {
					p.inScript = false

					for p.currentIndex < p.endIdx {
						p.skipWhitespace()

						if p.currentIndex >= p.endIdx ||
							p.data.GetByte(p.currentIndex) == 62 {
							break
						}

						var9 := p.currentIndex

						for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) > 32 && p.data.GetByte(p.currentIndex) != 62 {
							p.currentIndex++
						}

						if p.currentIndex >= p.endIdx {
							break
						}

						var10 := p.currentIndex

						var11Data, _ := p.data.SubSequence(var9, var10)
						var11 := utils.HTMLEntityDecode(var11Data.GetString())

						var8 = append(var8, &HTMLAttribute{
							Name:       var11,
							Value:      "",
							NameStart:  var9,
							NameEnd:    var10,
							ValueStart: p.currentIndex,
							ValueEnd:   p.currentIndex,
							QuoteType:  QuoteTypeNone,
						})
					}
				} else {
					if p.contentType == 0 && var4 == 0 {
						// Checking for void tags
						if var5 == "img" || var5 == "br" || var5 == "hr" || var5 == "meta" || var5 == "input" || var5 == "link" {
							var4 = SelfClosingTagOrPI
						}
					}

					p.inScript = (var5 == "script")

					for p.currentIndex < p.endIdx {
						p.skipWhitespace()

						if p.currentIndex >= p.endIdx || p.data.GetByte(p.currentIndex) == 62 {
							break
						}

						if p.data.GetByte(p.currentIndex) == 47 {
							var4 = SelfClosingTagOrPI

							p.currentIndex++
						} else {
							var21 := p.currentIndex

							for p.currentIndex < p.endIdx &&
								p.data.GetByte(p.currentIndex) > 32 &&
								p.data.GetByte(p.currentIndex) != 61 &&
								p.data.GetByte(p.currentIndex) != 47 &&
								p.data.GetByte(p.currentIndex) != 62 {
								p.currentIndex++
							}

							if p.currentIndex >= p.endIdx {
								break
							}

							var23 := p.currentIndex

							var24Data, _ := p.data.SubSequence(var21, var23)
							var24 := utils.HTMLEntityDecode(var24Data.GetString())

							p.skipWhitespace()

							if p.currentIndex >= p.endIdx {
								break
							}

							var12 := ""

							var13 := p.currentIndex

							var14 := p.currentIndex

							var15 := QuoteTypeNone

							if p.data.GetByte(p.currentIndex) == 61 {
								p.currentIndex++

								p.skipWhitespace()

								if p.currentIndex >= p.endIdx {
									break
								}

								var15 = p.getAttributeQuoteType()

								var13 = p.currentIndex

								p.parseAttributeValue(var15)

								var14 = p.currentIndex

								var12Data, _ := p.data.SubSequence(var13, var14)
								var12 = utils.HTMLEntityDecode(var12Data.GetString())

								switch var15 {
								case 0, 1, 2:
									p.currentIndex++
								}
							}

							if p.data.GetByte(var21) != 63 {
								var8 = append(var8, &HTMLAttribute{
									Name:       var24,
									Value:      var12,
									NameStart:  var21,
									NameEnd:    var23,
									ValueStart: var13,
									ValueEnd:   var14,
									QuoteType:  var15,
								})

							}

						}
					}
				}

				var22 := &HTMLTagInfo{
					Name:       var5,
					NameStart:  var2,
					NameEnd:    var7,
					Attributes: var8,
				}

				nextOffset := p.currentIndex + 1
				if nextOffset > p.endIdx {
					nextOffset = p.endIdx
				}
				p.elements = append(p.elements, &HTMLElement{
					Type:        var4,
					TagInfo:     var22,
					StartOffset: var20,
					EndOffset:   nextOffset,
				})

				p.currentIndex++
				continue
			}
		}

		return nil
	}
}

// removeInitialBom strips a Byte Order Mark (BOM) from the beginning of the content if present.
func (p *HTMLParser) removeInitialBom(var1 int, var2 *utils.ByteSequence) *utils.ByteSequence {
	for _, var4 := range bomSequences {
		if len(var4) <= var2.Length() && utils.ByteSequenceStartsWith(var2, var4, 0) {
			result, _ := p.data.SubSequence(var1+len(var4), p.currentIndex)
			return result
		}
	}

	return var2
}

// getContextForError returns a snippet of context around the current error position.
func (p *HTMLParser) getContextForError() string {
	contextStart := p.currentIndex - 20
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := p.currentIndex + 20
	if contextEnd > p.data.Length() {
		contextEnd = p.data.Length()
	}

	if contextStart > contextEnd {
		contextStart = contextEnd
	}

	contextData, _ := p.data.SubSequence(contextStart, contextEnd)
	return contextData.GetString()
}

// skipUntilTag advances past bytes until a tag-opening '<' is found or data ends.
// Handles CDATA sections specially in XML mode.
func (p *HTMLParser) skipUntilTag() {
	for p.currentIndex < p.endIdx {
		if p.contentType == 1 && p.currentIndex < p.endIdx-10 &&
			utils.ByteSequenceStartsWith(p.data, cdataStart, p.currentIndex) {
			var1 := utils.ByteSequenceIndexOfRange(p.data, cdataEnd, p.currentIndex, p.endIdx)
			if var1 != -1 {
				p.currentIndex = var1 + 3
			} else {
				p.currentIndex++
			}
		} else {
			if p.currentIndex+1 >= p.endIdx || p.data.GetByte(p.currentIndex) != 60 || !utils.ByteSequenceStartsWithCS(p.data, scriptTagEnd, false, p.currentIndex+1) && (!p.isPotentiallyOpenTagNameChar() || p.inScript) {
				p.currentIndex++
				continue
			}
			break
		}
	}
}

// GetElements returns the list of parsed HTMLElement instances.
func (p *HTMLParser) GetElements() []*HTMLElement {
	return p.elements
}

// parseAttributeValue reads an attribute value based on the quote type.
// Advances p.currentIndex to the position of the closing quote (if quoted).
func (p *HTMLParser) parseAttributeValue(quoteType QuoteType) {
	switch quoteType {
	case QuoteTypeDouble: // QuoteDouble
		for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) != 34 {
			p.currentIndex++
		}
	case QuoteTypeSingle: // QuoteSingle
		for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) != 39 {
			p.currentIndex++
		}
	case QuoteTypeBacktick: // QuoteBacktick
		for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) != 96 {
			p.currentIndex++
		}
	case QuoteTypeNone: // QuoteNone
		for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) > 32 && p.data.GetByte(p.currentIndex) != 62 {
			p.currentIndex++
		}
	default:
	}
}

// isPotentiallyOpenTagNameChar checks whether the character after '<' is valid for a tag name.
func (p *HTMLParser) isPotentiallyOpenTagNameChar() bool {
	char := p.data.GetByte(p.currentIndex + 1)
	return char > 32 && char != 46
}

// parseCommentOrDirective handles HTML comments (<!-- ... -->) and other directives (<!...>).
func (p *HTMLParser) parseCommentOrDirective() {
	startOffset := p.currentIndex
	isProperHtmlComment := false

	if p.currentIndex+3 < p.endIdx && p.data.GetByte(p.currentIndex+2) == 45 &&
		p.data.GetByte(p.currentIndex+3) == 45 {
		endCommentIndex := utils.ByteSequenceIndexOfRange(
			p.data,
			endComment,
			p.currentIndex+3,
			p.endIdx,
		)
		if endCommentIndex > 0 {
			p.currentIndex = endCommentIndex + 2
			isProperHtmlComment = true
		}
	}

	if !isProperHtmlComment {
		for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) != 62 {
			p.currentIndex++
		}
	}

	if p.currentIndex < p.endIdx {
		p.currentIndex++
	}

	contentData, _ := p.data.SubSequence(startOffset, p.currentIndex)
	p.elements = append(p.elements, &HTMLElement{
		Type:        CommentOrDirective,
		Content:     contentData.GetString(),
		StartOffset: startOffset,
		EndOffset:   p.currentIndex,
	})
}

// parseTagName reads the tag name from the current parser position.
// The tag name is lowercased. Advances p.currentIndex past the tag name.
func (p *HTMLParser) parseTagName() string {
	start := p.currentIndex

	for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) > 32 && p.data.GetByte(p.currentIndex) != 62 && p.data.GetByte(p.currentIndex) != 47 {
		p.currentIndex++
	}

	tagNameData, _ := p.data.SubSequence(start, p.currentIndex)
	return strings.ToLower(tagNameData.GetString())
}

// skipWhitespace skips whitespace characters (space, tab, newline, etc.).
// Advances p.currentIndex.
func (p *HTMLParser) skipWhitespace() {
	for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) <= 32 {
		p.currentIndex++
	}
}

// getAttributeQuoteType determines the quote type used for an attribute value.
// Advances p.currentIndex past the opening quote (if any).
// Returns the QuoteType (0: double, 1: single, 2: backtick, 3: none).
func (p *HTMLParser) getAttributeQuoteType() QuoteType {
	var1 := QuoteTypeNone
	if p.data.GetByte(p.currentIndex) == 34 {
		var1 = QuoteTypeDouble
		p.currentIndex++
	} else if p.data.GetByte(p.currentIndex) == 39 {
		var1 = QuoteTypeSingle
		p.currentIndex++
	} else if p.data.GetByte(p.currentIndex) == 96 {
		var1 = QuoteTypeBacktick
		p.currentIndex++
	}
	return var1
}

// --- Public Entry Points ---

// defaultStopSignal is the default stop signal that always returns false (never stops).
func defaultStopSignal() bool {
	return false
}

// ParseHTMLElements parses HTML/XML elements from the given byte slice.
// contentType: 0 for HTML, 1 for XML (affects CDATA handling and void tags).
// stopSignal: callback that can stop parsing early when it returns true.
func ParseHTMLElements(
	data []byte,
	offset int,
	limit int,
	contentType byte,
	mode ParseMode,
	stopSignal func() bool,
) ([]*HTMLElement, error) {
	byteData := utils.ByteSequenceFromBytes(data)
	if byteData == nil {
		return nil, fmt.Errorf("failed to create ByteSequence from input bytes")
	}

	parser := NewHTMLParser(byteData, offset, limit, contentType, mode)

	err := parser.parse(stopSignal)
	if err != nil {
		return nil, err
	}

	return parser.GetElements(), nil
}

// ParseHTMLElementsWithStop parses HTML/XML with ParseModeFull and a custom stopSignal.
func ParseHTMLElementsWithStop(
	data []byte,
	offset int,
	limit int,
	contentType byte,
	stopSignal func() bool,
) ([]*HTMLElement, error) {
	return ParseHTMLElements(data, offset, limit, contentType, ParseModeFull, stopSignal)
}

// ParseHTMLElementsSimple parses HTML/XML with ParseModeFull and no stopSignal.
func ParseHTMLElementsSimple(
	data []byte,
	offset int,
	limit int,
	contentType byte,
) ([]*HTMLElement, error) {
	return ParseHTMLElements(data, offset, limit, contentType, ParseModeFull, defaultStopSignal)
}
