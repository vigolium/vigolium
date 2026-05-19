package wordlist

import (
	"bytes"
	"context"
	"io"
)

// JSPreprocessor extracts string literals from JavaScript code.
type JSPreprocessor struct{}

// parserMode represents the current parsing state.
type parserMode byte

const (
	modeNormal       parserMode = iota
	modeDoubleQuote             // Inside "string"
	modeSingleQuote             // Inside 'string'
	modeBacktick                // Inside `template`
	modeLineComment             // After //
	modeBlockComment            // Inside /* */
	modeRegex                   // Inside /regex/
)

// Process extracts string literals from JavaScript.
// It handles single, double, and backtick quotes, and skips comments.
func (p *JSPreprocessor) Process(_ context.Context, reader io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	var stringBuf bytes.Buffer

	mode := modeNormal
	pos := 0
	end := len(data)

	for pos < end {
		ch := data[pos]

		switch mode {
		case modeNormal:
			switch ch {
			case '"':
				mode = modeDoubleQuote
				stringBuf.Reset()
			case '\'':
				mode = modeSingleQuote
				stringBuf.Reset()
			case '`':
				mode = modeBacktick
				stringBuf.Reset()
			case '/':
				if pos+1 < end {
					next := data[pos+1]
					switch next {
					case '/':
						mode = modeLineComment
						pos++
					case '*':
						mode = modeBlockComment
						pos++
					}
					// Don't try to parse regex - too complex and error-prone
				}
			}

		case modeDoubleQuote:
			if ch == '\\' && pos+1 < end {
				// Handle escape sequence
				next := data[pos+1]
				switch next {
				case 'n':
					stringBuf.WriteByte('\n')
				case 'r':
					stringBuf.WriteByte('\r')
				case 't':
					stringBuf.WriteByte('\t')
				case '\\':
					stringBuf.WriteByte('\\')
				case '"':
					stringBuf.WriteByte('"')
				case '\'':
					stringBuf.WriteByte('\'')
				default:
					// For other escapes, just include the escaped char
					stringBuf.WriteByte(next)
				}
				pos++
			} else if ch == '"' {
				// End of string
				if stringBuf.Len() > 0 {
					output.Write(stringBuf.Bytes())
					output.WriteByte(' ')
				}
				mode = modeNormal
			} else if ch == '\n' || ch == '\r' {
				// Unterminated string (newline in string literal is invalid)
				mode = modeNormal
			} else {
				stringBuf.WriteByte(ch)
			}

		case modeSingleQuote:
			if ch == '\\' && pos+1 < end {
				next := data[pos+1]
				switch next {
				case 'n':
					stringBuf.WriteByte('\n')
				case 'r':
					stringBuf.WriteByte('\r')
				case 't':
					stringBuf.WriteByte('\t')
				case '\\':
					stringBuf.WriteByte('\\')
				case '"':
					stringBuf.WriteByte('"')
				case '\'':
					stringBuf.WriteByte('\'')
				default:
					stringBuf.WriteByte(next)
				}
				pos++
			} else if ch == '\'' {
				if stringBuf.Len() > 0 {
					output.Write(stringBuf.Bytes())
					output.WriteByte(' ')
				}
				mode = modeNormal
			} else if ch == '\n' || ch == '\r' {
				mode = modeNormal
			} else {
				stringBuf.WriteByte(ch)
			}

		case modeBacktick:
			if ch == '\\' && pos+1 < end {
				next := data[pos+1]
				switch next {
				case 'n':
					stringBuf.WriteByte('\n')
				case 'r':
					stringBuf.WriteByte('\r')
				case 't':
					stringBuf.WriteByte('\t')
				case '\\':
					stringBuf.WriteByte('\\')
				case '`':
					stringBuf.WriteByte('`')
				case '$':
					stringBuf.WriteByte('$')
				default:
					stringBuf.WriteByte(next)
				}
				pos++
			} else if ch == '`' {
				if stringBuf.Len() > 0 {
					output.Write(stringBuf.Bytes())
					output.WriteByte(' ')
				}
				mode = modeNormal
			} else if ch == '$' && pos+1 < end && data[pos+1] == '{' {
				// Template literal interpolation ${...}
				// Output what we have so far and skip the interpolation
				if stringBuf.Len() > 0 {
					output.Write(stringBuf.Bytes())
					output.WriteByte(' ')
					stringBuf.Reset()
				}
				// Skip to closing brace (simplified - doesn't handle nested braces)
				depth := 1
				pos += 2 // Skip ${
				for pos < end && depth > 0 {
					switch data[pos] {
					case '{':
						depth++
					case '}':
						depth--
					}
					pos++
				}
				pos-- // Will be incremented at end of loop
			} else {
				stringBuf.WriteByte(ch)
			}

		case modeLineComment:
			if ch == '\n' || ch == '\r' {
				mode = modeNormal
			}
			// Otherwise skip comment characters

		case modeBlockComment:
			if ch == '*' && pos+1 < end && data[pos+1] == '/' {
				mode = modeNormal
				pos++
			}
			// Otherwise skip comment characters
		}

		pos++
	}

	return bytes.NewReader(output.Bytes()), nil
}

// ContentTypes returns the MIME types handled by this preprocessor.
func (p *JSPreprocessor) ContentTypes() []string {
	return []string{
		"/javascript",
		"/x-javascript",
		"/ecmascript",
	}
}
