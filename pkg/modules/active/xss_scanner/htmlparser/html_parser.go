package htmlparser

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// "fmt" // Sẽ dùng cho debug nếu cần
// Sẽ dùng cho các thao tác chuỗi

// Các hằng số byte array tương đương với các hằng số trong e7u.java
var (
	// endComment = []byte{'-', '-', '>'} // -->
	endComment = []byte{'-', '-', '>'}
	// cdataStart = []byte{'<', '!', '[', 'C', 'D', 'A', 'T', 'A', '['} // <![CDATA[
	cdataStart = []byte{'<', '!', '[', 'C', 'D', 'A', 'T', 'A', '['}
	// cdataEnd = []byte{']', ']', '>'} // ]]>
	cdataEnd = []byte{']', ']', '>'}
	// scriptTagEnd = []byte{'/', 's', 'c', 'r', 'i', 'p', 't'} // /script (dùng để kiểm tra </script>)
	scriptTagEnd = []byte{'/', 's', 'c', 'r', 'i', 'p', 't'}

	// bomSequences là danh sách các byte sequence (BOMs) cần loại bỏ ở đầu.
	// Tương đương với hằng số 'j' trong e7u.java
	bomSequences = [][]byte{
		{0, 0, 0xFE, 0xFF}, // UTF-32BE BOM
		{0xFF, 0xFE, 0, 0}, // UTF-32LE BOM
		{0xEF, 0xBB, 0xBF}, // UTF-8 BOM
		{0xFE, 0xFF},       // UTF-16BE BOM
		{0xFF, 0xFE},       // UTF-16LE BOM
	}
)

// HTMLParser là struct chính thực hiện việc phân tích HTML.
// Tương đương với lớp e7u trong Java.
type HTMLParser struct {
	startIdx     int            // Tương đương g (start offset trong data gốc)
	endIdx       int            // Tương đương d (end offset trong data gốc)
	data         *utils.Ac0     // Tương đương i (dữ liệu đầu vào)
	contentType  byte           // Tương đương h (0 for HTML, 1 for XML)
	parseMode    ParseMode      // Tương đương m (_9 enum)
	elements     []*HTMLElement // Tương đương k (danh sách các phần tử đã parse)
	currentIndex int            // Tương đương l (vị trí hiện tại đang parse)
	inScript     bool           // Tương đương c (true nếu đang ở trong thẻ <script>)
	// stopSignal     func() bool    // Hàm callback để dừng parse sớm nếu cần
}

// NewHTMLParser tạo một instance mới của HTMLParser.
// Tương đương với constructor e7u(int, int, bi9, byte, _9)
func NewHTMLParser(
	data *utils.Ac0,
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
		elements:     make([]*HTMLElement, 0), // Khởi tạo slice rỗng
		currentIndex: startIdx,                // Bắt đầu parse từ offset
		inScript:     false,
	}
}

// shouldStopForHTMLHead kiểm tra xem có nên dừng parse ở chế độ HEAD hay không.
// Tương đương với logic trong fl8.a của Java: fl8.a trả về true để tiếp tục, false để dừng,
// nên chúng ta cần đảo ngược logic trong hàm Go này.
func shouldStopForHTMLHead(elements []*HTMLElement, contentType byte, parseMode ParseMode) bool {
	if contentType != 0 /* HTML */ || parseMode != ParseModeHead {
		return false // Tiếp tục parse
	}
	if len(elements) == 0 {
		return false // Tiếp tục parse
	}
	lastElement := elements[len(elements)-1]
	isClosingHeadTag := lastElement.Type == CloseTag &&
		lastElement.TagInfo != nil &&
		strings.ToLower(lastElement.TagInfo.Name) == "head"
	return isClosingHeadTag // Dừng nếu là thẻ đóng </head>
}

// parse là phương thức chính thực hiện việc phân tích cú pháp HTML/XML.
// Tương đương với phương thức a(Supplier<Boolean> var1) trong e7u.java
func (p *HTMLParser) parse(var1 func() bool) (err error) {
	// Tương đương chính xác với a(Supplier<Boolean> var1) trong e7u.java
	defer func() {
		if var25 := recover(); var25 != nil {
			var2, ok := var25.(error)
			if !ok {
				var2 = fmt.Errorf("%v", var25)
			}

			// net.portswigger.m5.a(var2, this.d(), net.portswigger.rr.UNEXPECTED);
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

	// net.portswigger.qe.a(this.g >= 0 && this.g <= this.d && this.d <= this.i.aF(), net.portswigger.rg.j, (long)this.g, (long)this.d, (long)this.i.aF());
	p.currentIndex = p.startIdx // this.l = this.g;

	for {
		// if (var10000.l >= this.d || !fl8.a(this.k, this.h, this.m))
		if p.currentIndex >= p.endIdx ||
			shouldStopForHTMLHead(p.elements, p.contentType, p.parseMode) {
			zap.L().Debug("HTML parser reached end",
				zap.Int("startIdx", p.startIdx),
				zap.Int("endIdx", p.endIdx),
				zap.Int("currentIndex", p.currentIndex))
			return nil
		}

		// if ((Boolean)var1.get())
		if var1 != nil && var1() {
			return nil
		}

		// int var2 = var10000.l;
		var2 := p.currentIndex

		// this.c();
		p.skipUntilTag()

		// if (this.l > var18)
		if p.currentIndex > var2 {
			// bi9 var3 = this.i.a(var18, this.l);
			var3, _ := p.data.SubSequence(var2, p.currentIndex)

			// if (this.k.isEmpty())
			if len(p.elements) == 0 {
				// var3 = this.a(var18, var3);
				var3 = p.removeInitialBom(var2, var3)
			}

			// if (var3.aF() > 0)
			if var3.Length() > 0 {
				// this.k.add(new apb(var18, this.l, (byte)3, null, var3.x()));
				// p.elements = append(p.elements, &HTMLElement{
				// 	Type:        TextNode,         // (byte)3
				// 	Content:     var3.GetString(), // var3.x()
				// 	StartOffset: var18,
				// 	EndOffset:   p.currentIndex,
				// })
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
		// if p.currentIndex >= p.endIdx-1 {
		// 	break
		// }

		// if (this.l < this.d - 1)
		if p.currentIndex < p.endIdx-1 {
			// if (this.i.a(this.l + 1) == 33)
			if p.data.GetByte(p.currentIndex+1) == 33 {
				// this.f();
				p.parseCommentOrDirective()
				continue
			}

			// int var20 = this.l;
			var20 := p.currentIndex

			// byte var4 = 0;
			var4 := OpenTag

			// this.l++;
			p.currentIndex++

			// if (this.l < this.d && this.i.a(this.l) == 47)
			if p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) == 47 {
				// if (this.l + 1 < this.d && this.i.a(this.l + 1) == 46)
				if p.currentIndex+1 < p.endIdx && p.data.GetByte(p.currentIndex+1) == 46 {
					// this.f();
					p.parseCommentOrDirective()
					continue
				}

				// var4 = 1;
				var4 = CloseTag // CloseTag

				// this.l++;
				p.currentIndex++
			}

			// var18 = this.l;
			var2 = p.currentIndex

			// String var5 = this.b();
			var5 := p.parseTagName()

			// if (this.l < this.d)
			if p.currentIndex < p.endIdx {
				// int var7 = this.l;
				var7 := p.currentIndex

				// if (this.i.a(var18) == 63)
				if p.data.GetByte(var2) == 63 {
					// var4 = 4;
					var4 = 4 // SelfClosingTagOrPI
				}

				// acy var8 = new acy<>(ffv.a, 0);
				var8 := make([]*HTMLAttribute, 0)

				// if (var4 == 1)
				if var4 == 1 {
					// this.c = false;
					p.inScript = false

					// while (this.l < this.d)
					for p.currentIndex < p.endIdx {
						// this.e();
						p.skipWhitespace()

						// if (this.l >= this.d || this.i.a(this.l) == 62)
						if p.currentIndex >= p.endIdx ||
							p.data.GetByte(p.currentIndex) == 62 {
							break
						}

						// int var9 = this.l;
						var9 := p.currentIndex

						// while (this.l < this.d && this.i.a(this.l) > 32 && this.i.a(this.l) != 62)
						for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) > 32 && p.data.GetByte(p.currentIndex) != 62 {
							p.currentIndex++
						}

						// if (this.l >= this.d)
						if p.currentIndex >= p.endIdx {
							break
						}

						// int var10 = this.l;
						var10 := p.currentIndex

						// String var11 = net.portswigger.cy.c(this.i.a(var9, var10).x());
						var11Data, _ := p.data.SubSequence(var9, var10)
						var11 := utils.NetPortswiggerCyCHtmlEntityDecode(var11Data.GetString())

						// var8.add(new apy(var11, null, var9, var10, this.l, this.l, (byte)3));
						var8 = append(var8, &HTMLAttribute{
							Name:       var11,
							Value:      "", // null in Java
							NameStart:  var9,
							NameEnd:    var10,
							ValueStart: p.currentIndex,
							ValueEnd:   p.currentIndex,
							QuoteType:  QuoteTypeNone, // (byte)3
						})
					}
				} else {
					// if (this.h == 0 && var4 == 0 && (...))
					if p.contentType == 0 && var4 == 0 {
						// Checking for void tags
						if var5 == "img" || var5 == "br" || var5 == "hr" || var5 == "meta" || var5 == "input" || var5 == "link" {
							// var4 = 4;
							var4 = SelfClosingTagOrPI
						}
					}

					// this.c = "script".equals(var5);
					p.inScript = (var5 == "script")

					// while (this.l < this.d)
					for p.currentIndex < p.endIdx {
						// this.e();
						p.skipWhitespace()

						// if (this.l >= this.d || this.i.a(this.l) == 62)
						if p.currentIndex >= p.endIdx || p.data.GetByte(p.currentIndex) == 62 {
							break
						}

						// if (this.i.a(this.l) == 47)
						if p.data.GetByte(p.currentIndex) == 47 {
							// var4 = 4;
							var4 = SelfClosingTagOrPI

							// this.l++;
							p.currentIndex++
						} else {
							// int var21 = this.l;
							var21 := p.currentIndex

							// while (this.l < this.d && this.i.a(this.l) > 32 && this.i.a(this.l) != 61 && this.i.a(this.l) != 47 && this.i.a(this.l) != 62)
							for p.currentIndex < p.endIdx &&
								p.data.GetByte(p.currentIndex) > 32 &&
								p.data.GetByte(p.currentIndex) != 61 &&
								p.data.GetByte(p.currentIndex) != 47 &&
								p.data.GetByte(p.currentIndex) != 62 {
								p.currentIndex++
							}

							// if (this.l >= this.d)
							if p.currentIndex >= p.endIdx {
								break
							}

							// int var23 = this.l;
							var23 := p.currentIndex

							// String var24 = net.portswigger.cy.c(this.i.a(var21, var23).x());
							var24Data, _ := p.data.SubSequence(var21, var23)
							var24 := utils.NetPortswiggerCyCHtmlEntityDecode(var24Data.GetString())

							// this.e();
							p.skipWhitespace()

							// if (this.l >= this.d)
							if p.currentIndex >= p.endIdx {
								break
							}

							// String var12 = "";
							var12 := ""

							// int var13 = this.l;
							var13 := p.currentIndex

							// int var14 = this.l;
							var14 := p.currentIndex

							// byte var15 = 3;
							var15 := QuoteTypeNone // QuoteNone

							// if (this.i.a(this.l) == 61)
							if p.data.GetByte(p.currentIndex) == 61 {
								// this.l++;
								p.currentIndex++

								// this.e();
								p.skipWhitespace()

								// if (this.l >= this.d)
								if p.currentIndex >= p.endIdx {
									break
								}

								// var15 = this.a();
								var15 = p.getAttributeQuoteType()

								// var13 = this.l;
								var13 = p.currentIndex

								// this.a(var15);
								p.parseAttributeValue(var15)

								// var14 = this.l;
								var14 = p.currentIndex

								// var12 = net.portswigger.cy.c(this.i.a(var13, var14).x());
								var12Data, _ := p.data.SubSequence(var13, var14)
								var12 = utils.NetPortswiggerCyCHtmlEntityDecode(var12Data.GetString())

								// switch (var15)
								switch var15 {
								case 0, 1, 2:
									// this.l++;
									p.currentIndex++
									// if p.currentIndex < p.originalLimit && p.data.GetByte(p.currentIndex) == p.quoteChar(var15) {
									// 	p.currentIndex++
									// }
								}
							}

							// if (this.i.a(var21) != 63)
							if p.data.GetByte(var21) != 63 {
								// var8.add(new apy(var24, var12, var21, var23, var13, var14, var15));
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

				// apv var22 = new apv(var5, var18, var7, var8);
				// this.k.add(new apb(var20, Math.min(this.l + 1, this.d), var4, var22, null));
				// this.l++;
				// continue;
				var22 := &HTMLTagInfo{
					Name:       var5,
					NameStart:  var2,
					NameEnd:    var7,
					Attributes: var8,
				}

				// Math.min(this.l + 1, this.d)
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

				// this.l++;
				p.currentIndex++
				continue
			}
		}

		return nil
	}
}

// removeInitialBom loại bỏ Byte Order Mark (BOM) nếu có ở đầu của contentProvider.
// Tương đương với phương thức a(int var1, bi9 var2) trong e7u.java
func (p *HTMLParser) removeInitialBom(var1 int, var2 *utils.Ac0) *utils.Ac0 {
	for _, var4 := range bomSequences {
		if len(var4) <= var2.Length() && utils.CecStartsWithSimple(var2, var4, 0) {
			result, _ := p.data.SubSequence(var1+len(var4), p.currentIndex)
			return result
		}
	}

	return var2
}

// getContextForError trả về một đoạn context xung quanh vị trí lỗi hiện tại (p.currentIndex).
// Tương đương với phương thức d() trong e7u.java, nhưng chỉ trả về chuỗi context thô.
func (p *HTMLParser) getContextForError() string {
	contextStart := p.currentIndex - 20
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := p.currentIndex + 20
	if contextEnd > p.data.Length() {
		contextEnd = p.data.Length()
	}

	// Đảm bảo start không lớn hơn end, đặc biệt nếu p.data rất ngắn
	if contextStart > contextEnd {
		contextStart = contextEnd // Sẽ trả về chuỗi rỗng
	}

	contextData, _ := p.data.SubSequence(contextStart, contextEnd)
	return contextData.GetString()
}

// skipUntilTag bỏ qua các byte cho đến khi gặp ký tự bắt đầu một thẻ (`<`)
// hoặc kết thúc dữ liệu. Xử lý đặc biệt cho CDATA sections nếu là XML.
// Tương đương với phương thức c() trong e7u.java
func (p *HTMLParser) skipUntilTag() {
	for p.currentIndex < p.endIdx {
		if p.contentType == 1 && p.currentIndex < p.endIdx-10 &&
			utils.CecStartsWithSimple(p.data, cdataStart, p.currentIndex) {
			var1 := utils.CecIndexOfBytesRange(p.data, cdataEnd, p.currentIndex, p.endIdx)
			if var1 != -1 {
				p.currentIndex = var1 + 3
			} else {
				p.currentIndex++
			}
		} else {
			if p.currentIndex+1 >= p.endIdx || p.data.GetByte(p.currentIndex) != 60 || !utils.CecStartsWith(p.data, scriptTagEnd, false, p.currentIndex+1) && (!p.isPotentiallyOpenTagNameChar() || p.inScript) {
				p.currentIndex++
				continue
			}
			break
		}
	}
}

// GetElements trả về danh sách các HTMLElement đã được parse.
// Tương đương với phương thức h() trong e7u.java
func (p *HTMLParser) GetElements() []*HTMLElement {
	return p.elements
}

// parseAttributeValue đọc giá trị của một thuộc tính dựa trên loại quote.
// Cập nhật p.currentIndex đến vị trí của quote đóng (nếu có quote).
// Tương đương với phương thức a(byte var1) trong e7u.java.
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

// isPotentiallyOpenTagNameChar kiểm tra ký tự sau '<' có hợp lệ cho tên thẻ không.
// Tương đương với phương thức g() trong e7u.java
func (p *HTMLParser) isPotentiallyOpenTagNameChar() bool {
	char := p.data.GetByte(p.currentIndex + 1)
	return char > 32 && char != 46
}

// parseCommentOrDirective xử lý comment HTML (<!-- ... -->) và các directive khác (<!...>).
// Tương đương với phương thức f() trong e7u.java.
func (p *HTMLParser) parseCommentOrDirective() {
	startOffset := p.currentIndex
	isProperHtmlComment := false

	if p.currentIndex+3 < p.endIdx && p.data.GetByte(p.currentIndex+2) == 45 &&
		p.data.GetByte(p.currentIndex+3) == 45 {
		endCommentIndex := utils.CecIndexOfBytesRange(
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

// parseTagName đọc tên thẻ từ vị trí hiện tại của parser.
// Tên thẻ được chuyển thành chữ thường.
// Cập nhật p.currentIndex đến sau tên thẻ.
// Tương đương với phương thức b() trong e7u.java.
func (p *HTMLParser) parseTagName() string {
	start := p.currentIndex

	for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) > 32 && p.data.GetByte(p.currentIndex) != 62 && p.data.GetByte(p.currentIndex) != 47 {
		p.currentIndex++
	}

	tagNameData, _ := p.data.SubSequence(start, p.currentIndex)
	return strings.ToLower(tagNameData.GetString())
}

// skipWhitespace bỏ qua các ký tự whitespace (space, tab, newline, etc.).
// Cập nhật p.currentIndex.
// Tương đương với phương thức e() trong e7u.java.
func (p *HTMLParser) skipWhitespace() {
	for p.currentIndex < p.endIdx && p.data.GetByte(p.currentIndex) <= 32 {
		p.currentIndex++
	}
}

// getAttributeQuoteType xác định loại quote được sử dụng cho giá trị thuộc tính.
// Cập nhật p.currentIndex để bỏ qua quote mở (nếu có).
// Trả về byte đại diện cho loại quote (0: double, 1: single, 2: backtick, 3: none).
// Tương đương với phương thức a() trong e7u.java
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

// Thêm hàm helper nhỏ để lấy ký tự quote đóng
// func (p *HTMLParser) quoteChar(quoteType QuoteType) byte {
// 	switch quoteType {
// 	case QuoteTypeDouble:
// 		return '"'
// 	case QuoteTypeSingle:
// 		return '\''
// 	case QuoteTypeBacktick:
// 		return '`'
// 	}
// 	return 0 // Should not happen for valid quote types 0,1,2
// }

// --- Public Entry Points ---

// defaultStopSignal là một Supplier<Boolean> mặc định luôn trả về false (không dừng).
func defaultStopSignal() bool {
	return false
}

// ParseHTMLElements là hàm phân tích chính, đầy đủ nhất, tương đương với hàm static cuối cùng trong e7u.java.
// data: slice byte chứa nội dung HTML/XML.
// offset: vị trí bắt đầu phân tích trong data.
// limit: vị trí kết thúc phân tích trong data.
// contentType: 0 cho HTML, 1 cho XML (ảnh hưởng đến xử lý CDATA và void tags).
// mode: ParseMode (NONE, HEAD, FULL).
// stopSignal: hàm callback cho phép dừng phân tích sớm.
func ParseHTMLElements(
	data []byte,
	offset int,
	limit int,
	contentType byte,
	mode ParseMode,
	stopSignal func() bool,
) ([]*HTMLElement, error) {
	byteData := utils.Ac0FromBytes(data)
	if byteData == nil {
		return nil, fmt.Errorf("failed to create Ac0ByteData from input bytes")
	}

	// Điều chỉnh offset và limit cho ByteProvider, vì HTMLParser nhận offset/limit tương đối với ByteProvider được cắt sẵn.
	// Tuy nhiên, HTMLParser của chúng ta nhận offset/limit tuyệt đối với data gốc và ByteProvider gốc.
	// Nên không cần cắt ByteProvider ở đây.
	// e7u var6 = new e7u(var1, var2, var0, var3, var4);
	// var1 = offset, var2 = limit, var0 = byteProvider
	parser := NewHTMLParser(byteData, offset, limit, contentType, mode)

	// var6.a(var5); // var5 là stopSignal
	err := parser.parse(stopSignal)
	if err != nil {
		// và có thể thêm context từ parser.getContextForError()
		return nil, err
	}

	return parser.GetElements(), nil
}

// ParseHTMLElementsWithStop phân tích HTML/XML với ParseMode.FULL và một hàm stopSignal tùy chỉnh.
func ParseHTMLElementsWithStop(
	data []byte,
	offset int,
	limit int,
	contentType byte,
	stopSignal func() bool,
) ([]*HTMLElement, error) {
	return ParseHTMLElements(data, offset, limit, contentType, ParseModeFull, stopSignal)
}

// ParseHTMLElementsSimple phân tích HTML/XML với ParseMode.FULL và không có stopSignal (luôn parse hết hoặc đến khi gặp điều kiện dừng của mode).
func ParseHTMLElementsSimple(
	data []byte,
	offset int,
	limit int,
	contentType byte,
) ([]*HTMLElement, error) {
	return ParseHTMLElements(data, offset, limit, contentType, ParseModeFull, defaultStopSignal)
}
