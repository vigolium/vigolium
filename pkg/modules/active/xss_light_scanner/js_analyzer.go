package xss_light_scanner

// JSTokenType represents JavaScript token types
type JSTokenType int

const (
	JSTokenStringDouble JSTokenType = iota
	JSTokenStringSingle
	JSTokenStringBacktick
	JSTokenLineComment
	JSTokenBlockComment
	JSTokenCode
)

func (t JSTokenType) String() string {
	switch t {
	case JSTokenStringDouble:
		return "string_double"
	case JSTokenStringSingle:
		return "string_single"
	case JSTokenStringBacktick:
		return "string_backtick"
	case JSTokenLineComment:
		return "line_comment"
	case JSTokenBlockComment:
		return "block_comment"
	case JSTokenCode:
		return "code"
	default:
		return "unknown"
	}
}

// JSToken represents a JavaScript token with offset tracking
type JSToken struct {
	Type        JSTokenType
	StartOffset int
	EndOffset   int
}

// ContainsOffset checks if this token contains the given offset
func (t *JSToken) ContainsOffset(offset int) bool {
	return offset >= t.StartOffset && offset < t.EndOffset
}

// JavaScriptTokenizer tokenizes JavaScript content
type JavaScriptTokenizer struct{}

// NewJavaScriptTokenizer creates a new tokenizer
func NewJavaScriptTokenizer() *JavaScriptTokenizer {
	return &JavaScriptTokenizer{}
}

// Tokenize tokenizes JavaScript content into tokens
func (t *JavaScriptTokenizer) Tokenize(jsContent []byte, start, end int) []*JSToken {
	var tokens []*JSToken
	idx := start

	for idx < end {
		// Line comment //
		if idx+1 < end && jsContent[idx] == '/' && jsContent[idx+1] == '/' {
			commentEnd := t.findLineCommentEnd(jsContent, idx+2, end)
			tokens = append(tokens, &JSToken{
				Type:        JSTokenLineComment,
				StartOffset: idx,
				EndOffset:   commentEnd,
			})
			idx = commentEnd
			continue
		}

		// Block comment /* */
		if idx+1 < end && jsContent[idx] == '/' && jsContent[idx+1] == '*' {
			commentEnd := t.findBlockCommentEnd(jsContent, idx+2, end)
			tokens = append(tokens, &JSToken{
				Type:        JSTokenBlockComment,
				StartOffset: idx,
				EndOffset:   commentEnd,
			})
			idx = commentEnd
			continue
		}

		// Double-quoted string
		if jsContent[idx] == '"' {
			stringEnd := t.findStringEnd(jsContent, idx+1, end, '"')
			tokens = append(tokens, &JSToken{
				Type:        JSTokenStringDouble,
				StartOffset: idx,
				EndOffset:   stringEnd,
			})
			idx = stringEnd
			continue
		}

		// Single-quoted string
		if jsContent[idx] == '\'' {
			stringEnd := t.findStringEnd(jsContent, idx+1, end, '\'')
			tokens = append(tokens, &JSToken{
				Type:        JSTokenStringSingle,
				StartOffset: idx,
				EndOffset:   stringEnd,
			})
			idx = stringEnd
			continue
		}

		// Template literal (backtick)
		if jsContent[idx] == '`' {
			stringEnd := t.findStringEnd(jsContent, idx+1, end, '`')
			tokens = append(tokens, &JSToken{
				Type:        JSTokenStringBacktick,
				StartOffset: idx,
				EndOffset:   stringEnd,
			})
			idx = stringEnd
			continue
		}

		idx++
	}

	return tokens
}

// FindTokenAt finds the token containing the given offset
func (t *JavaScriptTokenizer) FindTokenAt(tokens []*JSToken, offset int) *JSToken {
	for _, token := range tokens {
		if token.ContainsOffset(offset) {
			return token
		}
	}
	return nil
}

func (t *JavaScriptTokenizer) findStringEnd(js []byte, start, end int, quoteChar byte) int {
	idx := start
	for idx < end {
		if js[idx] == '\\' {
			idx += 2
			continue
		}
		if js[idx] == quoteChar {
			return idx + 1
		}
		idx++
	}
	return end
}

func (t *JavaScriptTokenizer) findLineCommentEnd(js []byte, start, end int) int {
	idx := start
	for idx < end {
		if js[idx] == '\n' || js[idx] == '\r' {
			return idx + 1
		}
		idx++
	}
	return end
}

func (t *JavaScriptTokenizer) findBlockCommentEnd(js []byte, start, end int) int {
	idx := start
	for idx+1 < end {
		if js[idx] == '*' && js[idx+1] == '/' {
			return idx + 2
		}
		idx++
	}
	return end
}

// IsEscaped checks if the character at offset is escaped by backslashes
func (t *JavaScriptTokenizer) IsEscaped(content []byte, offset int) bool {
	if offset == 0 {
		return false
	}

	backslashCount := 0
	pos := offset - 1

	for pos >= 0 && content[pos] == '\\' {
		backslashCount++
		pos--
	}

	return backslashCount%2 == 1
}

// JavaScriptContextAnalyzer analyzes JavaScript context
type JavaScriptContextAnalyzer struct {
	tokenizer *JavaScriptTokenizer
}

// NewJavaScriptContextAnalyzer creates a new analyzer
func NewJavaScriptContextAnalyzer() *JavaScriptContextAnalyzer {
	return &JavaScriptContextAnalyzer{
		tokenizer: NewJavaScriptTokenizer(),
	}
}

// AnalyzeJavaScriptContext determines the reflection context within JavaScript
func (a *JavaScriptContextAnalyzer) AnalyzeJavaScriptContext(
	jsContent []byte,
	startOffset int,
	endOffset int,
	reflectionOffset int,
) ReflectionContext {
	// Decode HTML entities before tokenization
	decodedContent := a.decodeHtmlEntities(jsContent, startOffset, endOffset)

	// Calculate offset adjustment due to entity decoding
	adjustedReflectionOffset := a.calculateAdjustedOffset(jsContent, startOffset, reflectionOffset)

	tokens := a.tokenizer.Tokenize(decodedContent, 0, len(decodedContent))
	containingToken := a.tokenizer.FindTokenAt(tokens, adjustedReflectionOffset)

	if containingToken == nil {
		return JSCodeStatement
	}

	switch containingToken.Type {
	case JSTokenStringDouble:
		return JSStringDQBreakout
	case JSTokenStringSingle:
		return JSStringSQBreakout
	case JSTokenStringBacktick:
		return JSTemplateLiteral
	case JSTokenLineComment:
		return JSLineComment
	case JSTokenBlockComment:
		return JSBlockComment
	case JSTokenCode:
		return JSCodeStatement
	default:
		return JSCodeStatement
	}
}

func (a *JavaScriptContextAnalyzer) decodeHtmlEntities(content []byte, start, end int) []byte {
	section := content[start:end]
	return htmlDecode(section)
}

func (a *JavaScriptContextAnalyzer) calculateAdjustedOffset(content []byte, start, reflectionOffset int) int {
	beforeReflection := content[start:reflectionOffset]
	decodedBefore := htmlDecode(beforeReflection)
	return len(decodedBefore)
}

// AnalyzeJSContext is a convenience function for analyzing JS context
func AnalyzeJSContext(jsContent []byte, offset int) ReflectionContext {
	analyzer := NewJavaScriptContextAnalyzer()
	return analyzer.AnalyzeJavaScriptContext(jsContent, 0, len(jsContent), offset)
}
